#include <assert.h>
#include <glib.h>
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

static uint64_t icount;

static bool save_on_icount;
static bool save_on_address;

/* Map trigger addresses to exit code */
static GHashTable *addrs_ht;

/*
 * Ensure we left the TB before snapshoting the VM so the
 * cpu state is correctly updated before snapshoting
 */
bool tb_exited;

static void save_vm(void) {
    /* Save the VM and exit */
    qemu_plugin_savevm("snapshotfault");
    qemu_plugin_outs("Successfully saved the VM state !\n");
    exit(EXIT_SUCCESS);
}

static void icount_reached(unsigned int cpu_index, void *udata)
{
    uint64_t insn_vaddr = GPOINTER_TO_UINT(udata);
    if (!tb_exited) {
        tb_exited = true;
        char *msg = g_strdup_printf("icount reached at 0x%" PRIx64 ", exiting current TB\n",
                                    insn_vaddr);

        qemu_plugin_outs(msg);
        qemu_plugin_exit_current_tb();
    } else {
        save_vm();
    }
}

static void address_reached(unsigned int cpu_index, void *udata)
{
    uint64_t insn_vaddr = GPOINTER_TO_UINT(udata);
    if (!tb_exited) {
        tb_exited = true;
        char *msg = g_strdup_printf("0x%" PRIx64 " reached, exiting current TB\n", insn_vaddr);
        qemu_plugin_outs(msg);
        qemu_plugin_exit_current_tb();
    } else {
        save_vm();
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t tb_n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < tb_n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        gpointer insn_vaddr = GUINT_TO_POINTER(qemu_plugin_insn_vaddr(insn));

        if (save_on_icount) {
            /* Increment and check scoreboard for each instruction */
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
                insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_count, 1);

            qemu_plugin_register_vcpu_insn_exec_cond_cb(
                insn, icount_reached, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_COND_EQ, insn_count, icount + 1, insn_vaddr);

            /* Fired after we exited the TB */
            qemu_plugin_register_vcpu_insn_exec_cond_cb(
                insn, icount_reached, QEMU_PLUGIN_CB_NO_REGS,
                QEMU_PLUGIN_COND_EQ, insn_count, icount + 2, insn_vaddr);
        }

        if (save_on_address) {
            if (g_hash_table_contains(addrs_ht, insn_vaddr)) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, address_reached, QEMU_PLUGIN_CB_NO_REGS,
                    insn_vaddr);
            }
        }
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    qemu_plugin_outs("Exiting !\n");
    g_hash_table_destroy(addrs_ht);
    qemu_plugin_scoreboard_free(insn_count_sb);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    addrs_ht = g_hash_table_new(NULL, g_direct_equal);

    insn_count_sb = qemu_plugin_scoreboard_new(sizeof(InstructionsCount));
    insn_count = qemu_plugin_scoreboard_u64_in_struct(
        insn_count_sb, InstructionsCount, insn_count);

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "icount") == 0) {
            icount = g_ascii_strtoull(tokens[1], NULL, 0);
            if (icount < 1 || g_strrstr(tokens[1], "-") != NULL) {
                fprintf(stderr,
                        "icount parsing failed: '%s' must be a positive "
                        "integer\n",
                        tokens[1]);
                return -1;
            }
            save_on_icount = true;
        } else if (g_strcmp0(tokens[0], "addr") == 0) {
            g_auto(GStrv) addr_tokens = g_strsplit(tokens[1], ":", 2);
            uint64_t exit_addr = g_ascii_strtoull(addr_tokens[0], NULL, 0);
            int exit_code = 0;
            if (addr_tokens[1]) {
                exit_code = g_ascii_strtoull(addr_tokens[1], NULL, 0);
            }
            g_hash_table_insert(addrs_ht, GUINT_TO_POINTER(exit_addr),
                                GINT_TO_POINTER(exit_code));
            save_on_address = true;
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!save_on_icount && !save_on_address) {
        fprintf(stderr, "'icount' or 'addr' argument missing\n");
        return -1;
    }

    /* Register translation block and exit callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
