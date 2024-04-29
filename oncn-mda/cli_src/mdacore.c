/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
