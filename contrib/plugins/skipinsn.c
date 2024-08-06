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

static uint64_t max_insn;
static uint64_t executed_instructions;
static uint64_t begin_at;

static bool start_trigger;
static bool trigger_reached;

static GHashTable *insn_ht;
static GMutex hashtable_lock;

typedef struct {
    uint64_t address;
    size_t size;
} InsnInfo;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    InsnInfo *insn_info = udata;

    if (start_trigger && !trigger_reached && insn_info->address == begin_at) {
        trigger_reached = true;
    }

    if ((start_trigger && trigger_reached) || !start_trigger) {
        if (executed_instructions == max_insn) {
            executed_instructions++;
            char *msg = g_strdup_printf(
                "skipping instruction at address 0x%" PRIx64 "\n",
                insn_info->address);
            qemu_plugin_outs(msg);
            qemu_plugin_set_pc(insn_info->address + insn_info->size);
            msg = g_strdup_printf("pc has been set to 0x%" PRIx64 "\n",
                                  insn_info->address + insn_info->size);
            qemu_plugin_outs(msg);
            qemu_plugin_exit_current_tb();
        }

        executed_instructions++;
    }
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
            info->address = insn_vaddr;
            info->size = qemu_plugin_insn_size(insn);
            g_hash_table_insert(insn_ht, GUINT_TO_POINTER(insn_vaddr),
                                (gpointer)info);
        }
        g_mutex_unlock(&hashtable_lock);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, info);
    }
}

static void insn_free(gpointer data)
{
    InsnInfo *insn = data;
    g_free(insn);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_hash_table_destroy(insn_ht);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    char *msg;
    bool max_insn_set = false;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "after") == 0) {
            max_insn_set = true;
            max_insn = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "start") == 0) {
            start_trigger = true;
            begin_at = g_ascii_strtoull(tokens[1], NULL, 16);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!max_insn_set) {
        fprintf(stderr, "'after' should be specified");
        return -1;
    }

    if (start_trigger) {
        msg = g_strdup_printf("skipping once %" PRIu64
                              " instructions executed after 0x%" PRIx64
                              " is reached for the first time\n",
                              max_insn, begin_at);
    } else {
        msg = g_strdup_printf(
            "skipping after %" PRIu64 " instructions executed\n", max_insn);
    }

    qemu_plugin_outs(msg);
    insn_ht = g_hash_table_new_full(NULL, g_direct_equal, NULL, insn_free);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
