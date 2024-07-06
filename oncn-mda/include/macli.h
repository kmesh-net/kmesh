/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef MACLI_H
#define MACLI_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/mount.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "securec.h"
#include "data.h"
#include "log.h"

#define MAX_CIDR_LENGTH       19
#define MAX_IP_LENGTH         16
#define MAX_PORT_RANGE_LENGTH 12
#define MASK_LENGTH           32
#define MASK_BASE_NUM         2

#define CONFIGFILE_PATH         "/etc/oncn-mda/oncn-mda.conf"
#define BPF_PIN_FOLDER          "/sys/fs/bpf/meshAccelerate"
#define SOCK_OPS_PATH_INIT      "/usr/share/oncn-mda/sock_ops.c.o"
#define SOCK_REDIRECT_PATH_INIT "/usr/share/oncn-mda/sock_redirect.c.o"

struct input_filter_rule {
    int input_ip_num;
    int input_port_num;
#if MDA_GID_UID_FILTER
    int input_uid_num;
    int input_gid_num;
#endif
    char input_ip[MAX_PARAM_LENGTH][MAX_CIDR_LENGTH];
    char input_port[MAX_PARAM_LENGTH][MAX_PORT_RANGE_LENGTH];
#if MDA_GID_UID_FILTER
    __u32 input_uid[MAX_PARAM_LENGTH];
    __u32 input_gid[MAX_PARAM_LENGTH];
#endif
};

struct cmd {
    const char *cmd;
    int (*func)(int argc, char *const *argv);
};

enum MESH_MAP {
    // Do not modify the sequence, add later
    // This order already corresponds to the pin file name in g_pinMapFilePath during initialization
    MESH_MAP_OPS_MAP = 0,
#if MDA_GID_UID_FILTER
    MESH_MAP_OPS_HELPER_MAP,
#endif
    MESH_MAP_OPS_PARAM_MAP,
    MESH_MAP_OPS_PROXY_MAP,
    MESH_MAP_OPS_DUMP_I_MAP,
    MESH_MAP_OPS_DUMP_DATA_MAP,
    MESH_MAP_NUM
};

enum MESH_PROG {
    // Do not modify the sequence, add later
    // This order already corresponds to the pin file name in g_pinMapFilePath during initialization
    MESH_PROG_OPS = 0,
    MESH_PROG_REDIRECT,
    MESH_PROG_NUM
};

struct mesh_map_info {
    char name[BPF_OBJ_NAME_LEN];
    char pin_file_path[PATH_MAX];
    struct create_map_attr *xattr;
    int fd;
};

struct mesh_prog_info {
    char name[BPF_OBJ_NAME_LEN];
    char pin_file_path[PATH_MAX];
    struct object_open_attr *xattr;
    enum bpf_attach_type attach_type;
    int attach_fd;
    int fd;
};

struct mesh_service_info {
    struct mesh_map_info map_fds[MESH_MAP_NUM];
    struct mesh_prog_info prog_fds[MESH_PROG_NUM];
};

// global.c
int check_cidr(const char *const src, __u32 *const ip, __u32 *const mask);
int check_port(const char *const src, __u32 *const begin_port, __u32 *const end_port);
int init_fds(struct mesh_service_info *const fds, int cgroup_fd);
int get_u32_num(const char *const src, __u32 *const ret);
int get_cgroup_root_fd(void);
int get_map_filter_rule(const struct mesh_map_info *const param_map_info, struct sock_param *const param_list);

// query.c
int do_query(int argc, char *const *argv);
int check_accelerating_on(const struct mesh_service_info *const fds);

// switch.c
int do_enable(int argc, char *const *argv);
int do_disable(int argc, char *const *argv);
void close_fds(int cgroup_fd, const struct mesh_service_info *const fds);

// chain.c
int do_chain(int argc, char *const *argv, struct sock_param *const filter_rules);
#endif
