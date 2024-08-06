/*
 * Copyright (C) 2024, Simon Hamelin <simon.hamelin@grenoble-inp.org>
 *
 * Plugin that allow an user to iterate over all instructions of a binary
 * and determine if faulting them produce an undefined behavior
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

/* Options related variables */
static uint64_t fault_window_size;
static uint64_t fault_offset;
static uint64_t fault_step;
static uint64_t max_insns;
static uint64_t end_address;
static uint64_t error_addr;
static uint64_t faulted_addr;
static uint64_t num_faults;
static uint8_t set_value;
static bool strict_mode;
static bool use_set_fault_model;

static bool use_timeout;
static bool use_end_address;
static bool fault_address_set;
static bool fault_window_set;
static bool error_addr_set;

/* Hashmap that store instructions info */
static GHashTable *insn_ht;

typedef struct {
    uint64_t address;
    size_t size;
    GPtrArray *written_regs;
} InsnInfo;

/* Map register name to their id, used by the set fault model */
static GHashTable *register_ids_ht;

typedef struct {
    int register_id;
    int register_size;
} RegisterInfo;

/* Hold the indices of faults that will be applied in the current campaign */
static uint64_t *current_fault_config;
static uint64_t *current_faulted_addrs;

/* Indice of the next fault to be applied in the current campaign */
static uint64_t fault_indice;
static uint64_t executed_instructions;

/* Info about the current target instructions, used by the set fault model */
InsnInfo *target_instruction;


/**
 * Print the current configuration that led to a valid fault
 */
static void display_valid_fault_info(void)
{
    if (fault_indice == 0) {
        /* In this case the faulted address was reached without faulting */
        qemu_plugin_outs(g_strdup_printf(
                       "Successfully reached 0x%lx without faulting after %lu insn\n",
                       faulted_addr, executed_instructions));
        return;
    }

    GString *success_msg = g_string_new(NULL);
    g_string_append_printf(success_msg,
                           "Successfully reached 0x%lx by faulting the "
                           "following sequence of instruction: ",
                           faulted_addr);

    for (uint64_t i = 0; i < fault_indice - 1; i++) {
        g_string_append_printf(success_msg, "0x%lx after %lu insn -> ",
                               current_faulted_addrs[i],
                               current_fault_config[i]);
    }

    g_string_append_printf(success_msg, "0x%lx after %lu insn\n",
                           current_faulted_addrs[fault_indice - 1],
                           current_fault_config[fault_indice - 1]);

    qemu_plugin_outs(success_msg->str);
}


/**
 * Update the current fault configuration for the next campaign if possible
 * Example: if current_fault_config was [0, 1, 2] and fault_window_size = 10
 * then after calling this function current_fault_config will be [0, 1, 3].
 *          Another example still with fault_window_size = 10.
 *          Before call: current_fault_config = [0, 1, 9], after call
 * current_fault_config = [0, 2, 3]
 *
 * Return true if an update was possible, else false.
 */
static bool update_fault_instructions_indices(void)
{
    /* First determine indice of a fault offset than can be incremented */
    uint64_t i;
    bool possible = false;
    for (i = 0; i < num_faults; i++) {
        uint64_t val = current_fault_config[num_faults - i - 1];
        if (val < fault_window_size - i - 1) {
            possible = true;
            break;
        }
    }

    if (possible) {
        uint64_t next_val = current_fault_config[num_faults - i - 1];

        /* Then increment its value and the following one accordingly */
        for (uint64_t j = num_faults - i - 1; j < num_faults; j++) {
            current_fault_config[j] = ++next_val;
        }

        return true;
    }

    return false;
}

/**
 * Start a new fault campaign by updating fault
 * configuration or print results and exit if all fault configurations have been
 * done
 */
static void start_next_fault_campaign(void)
{
    qemu_plugin_outs("step\n");

    if (current_fault_config[0] == fault_window_size - num_faults) {
        /* In this case we tried all the possible configurations */
        exit(EXIT_SUCCESS);
    }

    /* Reset current fault experiment variables */
    executed_instructions = 0;
    fault_indice = 0;
    target_instruction = NULL;

    /* Determine the next set of instructions that should be faulted */
    for (uint64_t i=0; i < fault_step; i++) {
        if (!update_fault_instructions_indices()) {
            /* In this case there is no other possible configuration */
            exit(EXIT_SUCCESS);
        }
    }

    /* Reset system to its initial state so we can start a new fault campaign*/
    qemu_plugin_loadvm("snapshotfault");
    qemu_plugin_exit_current_tb();
}

/**
 * Callback executed everytime an instruction is about to be executed when using
 * set fault model
 */
static void vcpu_insn_exec_set(unsigned int cpu_index, void *udata)
{
    InsnInfo *insn_info = udata;

    if (fault_indice < num_faults &&
        executed_instructions == current_fault_config[fault_indice]) {
        target_instruction = insn_info;
        executed_instructions++;
    } else if (fault_indice < num_faults &&
               executed_instructions ==
                   current_fault_config[fault_indice] + 1 &&
               target_instruction != NULL) {
        /*
         * Iterate over all registers written by the instruction and
         * overwrite the result
         */
        if (target_instruction->written_regs->len > 0) {
            for (int i = 0; i < target_instruction->written_regs->len; i++) {
                char *reg_name = target_instruction->written_regs->pdata[i];
                RegisterInfo *reg_info =
                    g_hash_table_lookup(register_ids_ht, reg_name);

                if (reg_info != NULL) {
                    uint8_t *mem_buf = g_malloc0(reg_info->register_size);

                    for (int j = 0; j < reg_info->register_size; j++) {
                        mem_buf[j] = set_value;
                    }

                    qemu_plugin_write_register(
                        GINT_TO_POINTER(reg_info->register_id), mem_buf);
                }
            }
        }

        /* Update the current fault campaign variables */
        current_faulted_addrs[fault_indice] = target_instruction->address;
        fault_indice++;
        target_instruction = NULL;

        /*
         * Set PC to current insn addr to avoid re-executing the whole TB if
         * exiting midway
         */
        qemu_plugin_set_pc(insn_info->address);
        qemu_plugin_exit_current_tb();
    } else if (use_timeout &&
               executed_instructions >=
                   max_insns + current_fault_config[num_faults - 1]) {
        /* Assert we didn't go too far */
        g_assert(executed_instructions ==
                 max_insns + current_fault_config[num_faults - 1]);

        /*
         * We reached the maximum number of instructions we were allowed to
         * execute after faulting
         */
        qemu_plugin_outs("timeout\n");
        start_next_fault_campaign();
    } else if (use_end_address && insn_info->address == end_address) {
        /* The specified end address was reached */
        qemu_plugin_outs("endaddr\n");
        start_next_fault_campaign();
    } else if (insn_info->address == faulted_addr) {
        if ((strict_mode && fault_indice == num_faults) || !strict_mode) {
            display_valid_fault_info();
        }

        qemu_plugin_outs("fault\n");
        start_next_fault_campaign();
    } else if (insn_info->address == error_addr) {
        /* We reached the error handler address */
        qemu_plugin_outs("erroraddr\n");
        start_next_fault_campaign();
    } else {
        executed_instructions++;
    }
}

/**
 * Callback executed everytime an instruction is about to be executed when using
 * skip fault model
 */
static void vcpu_insn_exec_skip(unsigned int cpu_index, void *udata)
{
    InsnInfo *insn_info = udata;

    if (fault_indice < num_faults &&
        executed_instructions == current_fault_config[fault_indice]) {
        /* Inject the fault */
        qemu_plugin_set_pc(insn_info->address + insn_info->size);

        /* Update the current fault campaign variables */
        current_faulted_addrs[fault_indice] = insn_info->address;
        executed_instructions++;
        fault_indice++;

        /*
         * Exit the current TB so that PC modification is taken in account
         * Note that the following call never return
         */
        qemu_plugin_exit_current_tb();
    } else if (use_timeout &&
               executed_instructions >=
                   max_insns + current_fault_config[num_faults - 1]) {
        /* Assert we didn't go too far */
        g_assert(executed_instructions ==
                 max_insns + current_fault_config[num_faults - 1]);

        /*
         * We reached the maximum number of instructions we were allowed to
         * execute after faulting
         */
        qemu_plugin_outs("timeout\n");
        start_next_fault_campaign();
    } else if (use_end_address && insn_info->address == end_address) {
        /* The specified end address was reached */
        qemu_plugin_outs("endaddr\n");
        start_next_fault_campaign();
    } else if (insn_info->address == faulted_addr) {
        if ((strict_mode && fault_indice == num_faults) || !strict_mode) {
            display_valid_fault_info();
        }

        qemu_plugin_outs("fault\n");
        start_next_fault_campaign();
    } else if (insn_info->address == error_addr) {
        /* We reached the error handler address */
        qemu_plugin_outs("erroraddr\n");
        start_next_fault_campaign();
    } else {
        executed_instructions++;
    }
}

/**
 * Callback that register instructions callback everytime a TB is translated
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t tb_n = qemu_plugin_tb_n_insns(tb);
    InsnInfo *info;

    for (size_t i = 0; i < tb_n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);

        info = g_hash_table_lookup(insn_ht, GUINT_TO_POINTER(insn_vaddr));
        if (info == NULL) {
            info = g_new0(InsnInfo, 1);
            info->address = insn_vaddr;
            info->size = qemu_plugin_insn_size(insn);

            /* Written regs info will only be used by the set fault model*/
            if (use_set_fault_model) {
                info->written_regs = qemu_plugin_insn_disas_written_regs(insn);
            }

            g_hash_table_insert(insn_ht, GUINT_TO_POINTER(insn_vaddr),
                                (gpointer)info);
        }
        qemu_plugin_register_vcpu_insn_exec_cb(
            insn,
            use_set_fault_model ? vcpu_insn_exec_set : vcpu_insn_exec_skip,
            QEMU_PLUGIN_CB_NO_REGS, info);
    }
}

/**
 * Callback that populate the register_ids_ht map when a vpcu is initialized
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    g_autoptr(GArray) reg_list = qemu_plugin_get_registers();
    g_autoptr(GByteArray) reg_value = g_byte_array_new();

    if (reg_list) {
        for (int i = 0; i < reg_list->len; i++) {
            qemu_plugin_reg_descriptor *rd =
                &g_array_index(reg_list, qemu_plugin_reg_descriptor, i);

            int register_size =
                qemu_plugin_read_register(rd->handle, reg_value);
            g_assert(register_size > 0);

            RegisterInfo *reg_info = g_new0(RegisterInfo, 1);
            reg_info->register_id = GPOINTER_TO_INT(rd->handle);
            reg_info->register_size = register_size;
            g_hash_table_insert(register_ids_ht, (gpointer)rd->name, reg_info);
        }
    }
}

/**
 * Initialize some options default values
 */
static void initialize_default_options_values(void)
{
    num_faults = 1;
    fault_step = 1;
}

/**
 * Callback executed once the plugin exit
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (use_set_fault_model) {
        g_hash_table_destroy(register_ids_ht);
    }

    g_hash_table_destroy(insn_ht);
    g_free(current_fault_config);
    g_free(current_faulted_addrs);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    initialize_default_options_values();

    /* Parse options */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "timeout") == 0) {
            max_insns = g_ascii_strtoull(tokens[1], NULL, 10);
            use_timeout = true;
        } else if (g_strcmp0(tokens[0], "fault_model") == 0) {
            if (g_str_equal(tokens[1], "set")) {
                use_set_fault_model = true;
            } else if (g_str_equal(tokens[1], "skip")) {
                use_set_fault_model = false;
            } else {
                fprintf(stderr, "invalid fault model: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "fault_window") == 0) {
            fault_window_set = true;
            fault_window_size = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "fault_offset") == 0) {
            fault_offset = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "fault_step") == 0) {
            fault_step = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "end_addr") == 0) {
            end_address = g_ascii_strtoull(tokens[1], NULL, 16);
            use_end_address = true;
        } else if (g_strcmp0(tokens[0], "error_addr") == 0) {
            error_addr_set = true;
            error_addr = g_ascii_strtoull(tokens[1], NULL, 16);
        } else if (g_strcmp0(tokens[0], "faulted_addr") == 0) {
            fault_address_set = true;
            faulted_addr = g_ascii_strtoull(tokens[1], NULL, 16);
        } else if (g_strcmp0(tokens[0], "num_fault") == 0) {
            num_faults = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "set_value") == 0) {
            set_value = g_ascii_strtoull(tokens[1], NULL, 0) & 0xFF;
        } else if (g_strcmp0(tokens[0], "strict") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &strict_mode)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    /* Initialize fault campaign variables */
    if (use_set_fault_model) {
        register_ids_ht =
            g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
    }
    insn_ht = g_hash_table_new_full(NULL, g_direct_equal, NULL, g_free);
    current_fault_config = g_new0(uint64_t, num_faults);
    current_faulted_addrs = g_new0(uint64_t, num_faults);

    /* Initialize the first fault configuration indices */
    for (uint64_t i = 0; i < num_faults; ++i) {
        current_fault_config[i] = i;
    }

    /* Set the correct fault configuration matching the offset */
    for (uint64_t i = 0; i < fault_offset; ++i) {
        update_fault_instructions_indices();
    }

    /* Register CPU init, TB translation and exit callback*/
    if (use_set_fault_model) {
        qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
