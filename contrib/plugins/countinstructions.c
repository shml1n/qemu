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

static uint64_t start_address;
static uint64_t end_address;
static uint64_t executed_insns;

bool start_reached;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    uint64_t insn_vaddr = GPOINTER_TO_UINT(udata);

    if (!start_reached) {
        if (insn_vaddr == start_address) {
            start_reached = true;
        } else {
            return;
        }
    }

    if (start_reached) {
        executed_insns++;

        if (insn_vaddr == end_address) {
            qemu_plugin_outs(g_strdup_printf("%lu instructions executed between start and end address\n", executed_insns));
            exit(EXIT_SUCCESS);
        }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t tb_n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < tb_n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, GUINT_TO_POINTER(insn_vaddr));
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    bool start_address_set = false;
    bool end_address_set = false;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "start") == 0) {
            start_address_set = true;
            start_address = g_ascii_strtoull(tokens[1], NULL, 16);
        } else if (g_strcmp0(tokens[0], "end") == 0) {
            end_address_set = true;
            end_address = g_ascii_strtoull(tokens[1], NULL, 16);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    if (!start_address_set || !end_address_set) {
        fprintf(stderr, "'start' and 'end' should be specified");
        return -1;
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
