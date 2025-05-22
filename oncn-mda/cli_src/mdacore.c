// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "macli.h"

static void usage(void)
{
    (void)printf("Usage: mdacore {COMMAND}\n");
    (void)printf("       COMMAND: enable      enable serviceMesh accelerating\n");
    (void)printf("                disable     disable serviceMesh accelerating\n");
    (void)printf("                query       check program state\n");
}

static int do_help(int argc, char *const *argv)
{
    usage();
    return 0;
}

const struct cmd mda_cmds[] = {
    {"help", do_help},       // help message
    {"enable", do_enable},   // enable service
    {"disable", do_disable}, // disable service
    {"query", do_query},     // query service is enabled
    {NULL}};

static int cmd_select(const struct cmd *cmds, int argc, char *const *argv, int (*help)(int argc, char *const *argv))
{
    for (int i = 0; cmds[i].func; ++i) {
        if (strcmp(*argv, cmds[i].cmd) == 0)
            return cmds[i].func(argc, argv);
    }

    help(argc - 1, argv + 1);

    return ERROR;
}

int main(int argc, char **argv)
{
    argc -= optind;
    argv += optind;
    if (argc <= 0) {
        usage();
        return FAILED;
    }
    (void)libbpf_set_print(NULL);
    return cmd_select(mda_cmds, argc, argv, do_help);
}
