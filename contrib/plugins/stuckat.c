/*
 * Copyright (C) 2024, Simon Hamelin <simon.hamelin@grenoble-inp.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* Scoreboard to track executed instructions count */
typedef struct {
    uint64_t insn_count;
} InstructionsCount;
static struct qemu_plugin_scoreboard *insn_count_sb;
static qemu_plugin_u64 insn_count;

static GHashTable *insn_ht;
static GMutex hashtable_lock;

typedef struct {
    uint64_t vaddr;
    uint32_t opcode;
    char *disas;
    GPtrArray *written_regs;
} InsnInfo;

static uint64_t icount;

/* Instruction we want to fault*/
InsnInfo *target_instruction;

/* Map register name to their id */
static GHashTable *register_ids;
static GMutex register_ids_ht_lock;

typedef struct {
    int register_id;
    int register_size;
} RegisterInfo;

// static void get_register_number_by_name()

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
    g_autoptr(GByteArray) reg_value = g_byte_array_new();

    if (reg_list) {
        for (int i = 0; i < reg_list->len; i++) {
            qemu_plugin_reg_descriptor *rd = &g_array_index(
                reg_list, qemu_plugin_reg_descriptor, i);

            int register_size = qemu_plugin_read_register(rd->handle, reg_value);
            g_assert(register_size > 0);

            qemu_plugin_outs(g_strdup_printf("Register %s has id %d and size %d\n", rd->name, GPOINTER_TO_INT(rd->handle), register_size));

            g_mutex_lock(&register_ids_ht_lock);
            RegisterInfo *reg_info = g_new0(RegisterInfo, 1);

            reg_info->register_id = GPOINTER_TO_INT(rd->handle);
            reg_info->register_size = register_size;

            g_hash_table_insert(register_ids, (gpointer)rd->name, reg_info);
            g_mutex_unlock(&register_ids_ht_lock);
        }
    }
}

static void insert_stuckat_fault(unsigned int cpu_index, void *udata) {
    InsnInfo *insn_info = udata;
    qemu_plugin_outs(g_strdup_printf("Setting written registers of instruction 0x%lx to 0 before executing instruction 0x%lx\n", target_instruction->vaddr, insn_info->vaddr));

    /* Inject the fault here */
    if (target_instruction->written_regs->len > 0) {
        for (int i = 0; i < target_instruction->written_regs->len; i++) {
            char *reg_name = target_instruction->written_regs->pdata[i];
            qemu_plugin_outs(g_strdup_printf("Searching info for register %s\n", reg_name));
            g_mutex_lock(&register_ids_ht_lock);
            RegisterInfo *reg_info = g_hash_table_lookup(register_ids, reg_name);

            if (reg_info != NULL) {
                uint8_t *mem_buf = g_malloc0(reg_info->register_size);

                for (int i = 0; i < reg_info->register_size; ++i) {
                    mem_buf[i] = 0xFF;
                }

                qemu_plugin_write_register(GINT_TO_POINTER(reg_info->register_id), mem_buf);
                qemu_plugin_outs(g_strdup_printf("Wrote %d null bytes to register %s\n", reg_info->register_size, reg_name));
            } else {
                qemu_plugin_outs(g_strdup_printf("Register %s cannot be written as its info cannot be found\n", reg_name));
            }
            g_mutex_unlock(&register_ids_ht_lock);
        }
    } else {
        qemu_plugin_outs("No destination registers to fault for this target instruction");
    }

    /* Set PC to current insn addr to avoid re-executing the whole TB if exiting midway */
    qemu_plugin_set_pc(insn_info->vaddr);
    qemu_plugin_exit_current_tb();
}

static void icount_reached(unsigned int cpu_index, void *udata) {
    InsnInfo *insn_info = udata;

    GString *msg = g_string_new(NULL);

    g_string_append_printf(msg, "Instruction %lu is at address 0x%lx, opcode is 0x%x\n", icount, insn_info->vaddr, insn_info->opcode);
    g_string_append_printf(msg, "Disassembly: %s\n", insn_info->disas);

    if (insn_info->written_regs->len > 0) {
        g_string_append(msg, "Written regs: [");

        for (int i = 0; i < insn_info->written_regs->len - 1; i++) {
            g_string_append_printf(msg, "%s, ", (char *)insn_info->written_regs->pdata[i]);
        }

        g_string_append_printf(msg, "%s]\n", (char *)insn_info->written_regs->pdata[insn_info->written_regs->len - 1]);
    }

    qemu_plugin_outs(msg->str);
    target_instruction = insn_info;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t tb_n = qemu_plugin_tb_n_insns(tb);
    InsnInfo *info;

    for (size_t i = 0; i < tb_n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);

        g_mutex_lock(&hashtable_lock);
        info = g_hash_table_lookup(insn_ht, GUINT_TO_POINTER(insn_vaddr));
        if (info == NULL) {
            info = g_new0(InsnInfo, 1);
            info->vaddr = insn_vaddr;
            qemu_plugin_insn_data(insn, &info->opcode, sizeof(info->opcode));
            info->disas = qemu_plugin_insn_disas(insn);
            info->written_regs = qemu_plugin_insn_disas_written_regs(insn);
            g_hash_table_insert(insn_ht, GUINT_TO_POINTER(insn_vaddr),info);
        }
        g_mutex_unlock(&hashtable_lock);
        /* Increment and check scoreboard for each instruction */
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_count, 1);

        /* First callback that will set the written regs number */
        qemu_plugin_register_vcpu_insn_exec_cond_cb(
            insn, icount_reached, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_COND_EQ, insn_count, icount + 1, info);

        /* Second callback that will fire after the targeted instruction executed and replace
         * values in the written registers with 0 or 0xFF
         */
        qemu_plugin_register_vcpu_insn_exec_cond_cb(
            insn, insert_stuckat_fault, QEMU_PLUGIN_CB_RW_REGS,
            QEMU_PLUGIN_COND_EQ, insn_count, icount + 2, info);
    }
}

static void free_insn_info(gpointer data) {
    InsnInfo *info = data;
    g_free(info->disas);
    g_free(info->written_regs);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_hash_table_destroy(insn_ht);
    qemu_plugin_scoreboard_free(insn_count_sb);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    register_ids = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
    insn_ht = g_hash_table_new_full(NULL, g_direct_equal, NULL, free_insn_info);
    insn_count_sb = qemu_plugin_scoreboard_new(sizeof(InstructionsCount));
    insn_count = qemu_plugin_scoreboard_u64_in_struct(
        insn_count_sb, InstructionsCount, insn_count);

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "icount") == 0) {
            icount = g_ascii_strtoull(tokens[1], NULL, 10);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
