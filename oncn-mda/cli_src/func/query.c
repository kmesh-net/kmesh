// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include "macli.h"

static void query_usage(void)
{
    (void)printf("usage: mdacore query {OPTIONS}\n");
    (void)printf("       OPTIONS: -h|--help:         print usage\n");
}

static const struct option query_options[] = {{"help", no_argument, NULL, 'h'}, {NULL}};

static int query_get_opt(int argc, char *const *argv, bool *const is_help)
{
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "h", query_options, NULL)) >= 0) {
        switch (opt) {
        case 'h':
            query_usage();
            *is_help = true;
            break;
        case '?':
        default:
            query_usage();
            return FAILED;
        }
    }
    if (optind != argc) {
        macli_log(ERR, "unknown param!\n");
        query_usage();
        return FAILED;
    }
    return SUCCESS;
}

static int get_attach_prog_fd(int attach_fd, enum bpf_attach_type type, const char *const prog_name)
{
    __u32 prog_ids[10] = {0};
    __u32 prog_cnt = 10;
    if (attach_fd < 0)
        return ERROR;
    if (bpf_prog_query(attach_fd, type, 0, NULL, prog_ids, &prog_cnt)) {
        macli_log(ERR, "bpf prog query failed! errno:%d\n", errno);
        return ERROR;
    }
    for (__u32 iter = 0; iter < prog_cnt; ++iter) {
        struct bpf_prog_info info = {};
        __u32 info_len = sizeof(info);
        int prog_fd = bpf_prog_get_fd_by_id(prog_ids[iter]);
        if (prog_fd < 0) {
            macli_log(ERR, "get prog fd failed! errno:%d\n", errno);
            return ERROR;
        }
        if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
            macli_log(ERR, "read bpf info failed! errno:%d\n", errno);
            (void)close(prog_fd);
            return ERROR;
        }
        if (strcmp(info.name, prog_name) == 0)
            return prog_fd;
        (void)close(prog_fd);
    }
    return ERROR;
}

static int query_prog_attach(int attach_fd, enum bpf_attach_type type, const char *const prog_name)
{
    /*
     * query whether an EBPF program is mounted under a FD
     * param: attach_fd: The mounted FD can be a Cgroup FD or a Map FD
     *	  type: mount type
     *	  prog_name: ebpf program name
     */
    int fd = get_attach_prog_fd(attach_fd, type, prog_name);
    if (fd < 0)
        return FALSE;
    (void)close(fd);
    return TRUE;
}

int check_accelerating_on(const struct mesh_service_info *const fds)
{
    /*
     * Check that the acceleration function is enabled
     * param: struct mesh_service_info
     * return:  TRUE
     *		  FALSE
     *		  ERROR
     */
    unsigned int success_num = 0;
    for (unsigned int i = 0; i < MESH_PROG_NUM; ++i) {
        if (query_prog_attach(fds->prog_fds[i].attach_fd, fds->prog_fds[i].attach_type, fds->prog_fds[i].name) == TRUE)
            success_num++;
    }
    if (success_num == 0)
        return FALSE;
    else if (success_num == MESH_PROG_NUM)
        return TRUE;
    return ERROR;
}

int do_query(int argc, char *const *argv)
{
    bool is_help = false;
    if (query_get_opt(argc, argv, &is_help))
        return ERROR;

    if (is_help)
        return SUCCESS;

    int cgroup_fd = get_cgroup_root_fd();
    if (cgroup_fd < 0) {
        macli_log(ERR, "query failed!\n");
        return ERROR;
    }

    struct mesh_service_info fds;
    if (init_fds(&fds, cgroup_fd) != SUCCESS) {
        close_fds(cgroup_fd, &fds);
        return ERROR;
    }

    int ret = check_accelerating_on(&fds);
    close_fds(cgroup_fd, &fds);
    if (ret == TRUE)
        macli_log(INFO, "serviceMesh accelerating is enabled!\n");
    else if (ret == FALSE)
        macli_log(INFO, "serviceMesh accelerating is disabled!\n");
    else
        macli_log(INFO, "serviceMesh accelerating get some error!\n");

    return ret;
}
