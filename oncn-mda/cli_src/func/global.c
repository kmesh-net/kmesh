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

#include <mntent.h>
#include <ctype.h>
#include "macli.h"

#define TMP_BUF_SIZE 50

const char pinmap_file_path[][PATH_MAX] = {
    "/sys/fs/bpf/meshAccelerate/sock_ops_map",
#if MDA_GID_UID_FILTER
    "/sys/fs/bpf/meshAccelerate/sock_helper_map",
#endif
    "/sys/fs/bpf/meshAccelerate/sock_param_map",
    "/sys/fs/bpf/meshAccelerate/sock_proxy_map",
    "/sys/fs/bpf/meshAccelerate/sock_dump_map",
    "/sys/fs/bpf/meshAccelerate/sock_dump_data_map"};

const char pinprog_file_path[][PATH_MAX] = {
    "/sys/fs/bpf/meshAccelerate/sock_ops_ip4",
    "/sys/fs/bpf/meshAccelerate/sock_redirect",
};

struct bpf_create_map_attr g_sock_param_map_xattr = {
    .name = to_str(SOCK_PARAM_MAP_NAME),
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sock_param),
    .max_entries = 1,
};

struct bpf_create_map_attr g_sock_ops_map_xattr = {
    .name = to_str(SOCK_OPS_MAP_NAME),
    .map_type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(int),
    .max_entries = SKOPS_MAP_SIZE,
};

#if MDA_GID_UID_FILTER
struct bpf_create_map_attr g_sock_ops_helper_map_xattr = {
    .name = to_str(SOCK_OPS_HELPER_MAP_NAME),
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(struct uid_gid_info),
    .max_entries = SKOPS_MAP_SIZE,
};
#endif

struct bpf_create_map_attr g_sock_ops_proxy_map_xattr = {
    .name = to_str(SOCK_OPS_PROXY_MAP_NAME),
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(struct sock_key),
    .max_entries = SKOPS_MAP_SIZE,
};

struct bpf_create_map_attr g_sock_dump_map = {
    .name = to_str(SOCK_DUMP_MAP_I_NAME),
    .map_type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(struct dump_data),
    .max_entries = DUMP_QUEUE_LENGTH,
};

struct bpf_create_map_attr g_sock_dump_data_map = {
    .name = to_str(SOCK_DUMP_CPU_ARRAY_NAME),
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct dump_data),
    .max_entries = 1,
};

struct bpf_object_open_attr g_sock_ops_xattr = {
    .prog_type = BPF_PROG_TYPE_SOCK_OPS,
    .file = SOCK_OPS_PATH_INIT,
};

struct bpf_object_open_attr g_sock_redirect_xattr = {
    .prog_type = BPF_PROG_TYPE_SK_MSG,
    .file = SOCK_REDIRECT_PATH_INIT,
};

static int get_prog_fd(const char *const prog_name, int *const fd)
{
    *fd = ERROR;
    struct bpf_prog_info prog_info = {0};
    __u32 obj_id = 0;
    __u32 info_length = sizeof(struct bpf_prog_info);
    while (true) {
        if (memset_s(&prog_info, info_length, 0x0, info_length) != EOK) {
            macli_log(ERR, "system memset failed!\n");
            return FAILED;
        }
        if (bpf_prog_get_next_id(obj_id, &obj_id)) {
            if (errno == ENOENT)
                break;
            macli_log(ERR, "can not read bpf prog info! errno:%d\n", errno);
            return FAILED;
        }
        int obj_fd = bpf_prog_get_fd_by_id(obj_id);
        if (obj_fd < 0) {
            if (errno == ENOENT)
                continue;
            macli_log(ERR, "can not read bpf prog info! errno:%d\n", errno);
            return FAILED;
        }
        if (bpf_obj_get_info_by_fd(obj_fd, &prog_info, &info_length)) {
            macli_log(ERR, "can not read bpf prog info! errno:%d\n", errno);
            (void)close(obj_fd);
            return FAILED;
        }
        if (strcmp(prog_info.name, prog_name) == 0) {
            *fd = obj_fd;
            return SUCCESS;
        }
        (void)close(obj_fd);
    }
    return SUCCESS;
}

static int get_map_fd(const char *const map_name, int *const fd)
{
    *fd = ERROR;
    struct bpf_map_info map_info = {0};
    __u32 obj_id = 0;
    __u32 info_length = sizeof(struct bpf_map_info);
    while (true) {
        if (memset_s(&map_info, info_length, 0x0, info_length) != EOK) {
            macli_log(ERR, "system memset failed!\n");
            return FAILED;
        }
        if (bpf_map_get_next_id(obj_id, &obj_id)) {
            if (errno == ENOENT)
                break;
            macli_log(ERR, "can not read bpf map info! errno:%d\n", errno);
            return FAILED;
        }
        int obj_fd = bpf_map_get_fd_by_id(obj_id);
        if (obj_fd < 0) {
            if (errno == ENOENT)
                continue;
            macli_log(ERR, "can not read bpf map info! errno:%d\n", errno);
            return FAILED;
        }
        if (bpf_obj_get_info_by_fd(obj_fd, &map_info, &info_length)) {
            macli_log(ERR, "can not read bpf map info! errno:%d\n", errno);
            (void)close(obj_fd);
            return FAILED;
        }
        if (strcmp(map_info.name, map_name) == 0) {
            *fd = obj_fd;
            return SUCCESS;
        }
        (void)close(obj_fd);
    }
    return SUCCESS;
}

static int init_mesh_map(
    struct mesh_map_info *const fds_map,
    const char *const pin_file_path,
    const char *const map_name,
    struct bpf_create_map_attr *const map_attr)
{
    int ret = EOK;
    ret += strcpy_s(fds_map->name, BPF_OBJ_NAME_LEN, map_name);
    ret += strcpy_s(fds_map->pin_file_path, PATH_MAX, pin_file_path);
    if (ret != EOK) {
        macli_log(ERR, "system copy string failed!");
        return FAILED;
    }
    if (get_map_fd(fds_map->name, &(fds_map->fd)) != SUCCESS)
        return FAILED;
    fds_map->xattr = map_attr;
    return SUCCESS;
}

static int init_mesh_prog(
    struct mesh_prog_info *const fds_prog,
    const char *const prog_name,
    struct bpf_object_open_attr *const prog_attr,
    enum bpf_attach_type attach_type,
    int attach_fd)
{
    int ret = EOK;
    ret = strcpy_s(fds_prog->name, BPF_OBJ_NAME_LEN, prog_name);
    if (ret != EOK) {
        macli_log(ERR, "system copy string failed!");
        return FAILED;
    }
    if (get_prog_fd(fds_prog->name, &(fds_prog->fd)) != SUCCESS)
        return FAILED;
    fds_prog->attach_type = attach_type;
    fds_prog->attach_fd = attach_fd;
    fds_prog->xattr = prog_attr;
    return SUCCESS;
}

static int init_mesh_prog_pin_file(struct mesh_prog_info *const fds_prog, const char *const pin_file_path)
{
    int ret = EOK;
    ret = strcpy_s(fds_prog->pin_file_path, PATH_MAX, pin_file_path);
    if (ret != EOK) {
        macli_log(ERR, "system copy string failed!");
        return FAILED;
    }

    return SUCCESS;
}

int init_fds(struct mesh_service_info *const fds, int cgroup_fd)
{
    int ret = SUCCESS;
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_MAP],
        pinmap_file_path[MESH_MAP_OPS_MAP],
        to_str(SOCK_OPS_MAP_NAME),
        &g_sock_ops_map_xattr);
#if MDA_GID_UID_FILTER
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_HELPER_MAP],
        pinmap_file_path[MESH_MAP_OPS_HELPER_MAP],
        to_str(SOCK_OPS_HELPER_MAP_NAME),
        &g_sock_ops_helper_map_xattr);
#endif
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_PARAM_MAP],
        pinmap_file_path[MESH_MAP_OPS_PARAM_MAP],
        to_str(SOCK_PARAM_MAP_NAME),
        &g_sock_param_map_xattr);
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_PROXY_MAP],
        pinmap_file_path[MESH_MAP_OPS_PROXY_MAP],
        to_str(SOCK_OPS_PROXY_MAP_NAME),
        &g_sock_ops_proxy_map_xattr);
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_DUMP_I_MAP],
        pinmap_file_path[MESH_MAP_OPS_DUMP_I_MAP],
        to_str(SOCK_DUMP_MAP_I_NAME),
        &g_sock_dump_map);
    ret += init_mesh_map(
        &fds->map_fds[MESH_MAP_OPS_DUMP_DATA_MAP],
        pinmap_file_path[MESH_MAP_OPS_DUMP_DATA_MAP],
        to_str(SOCK_DUMP_CPU_ARRAY_NAME),
        &g_sock_dump_data_map);
    ret += init_mesh_prog(
        &fds->prog_fds[MESH_PROG_OPS], to_str(SOCK_OPS_NAME), &g_sock_ops_xattr, BPF_CGROUP_SOCK_OPS, cgroup_fd);
    ret += init_mesh_prog_pin_file(&fds->prog_fds[MESH_PROG_OPS], pinprog_file_path[MESH_PROG_OPS]);
    ret += init_mesh_prog(
        &fds->prog_fds[MESH_PROG_REDIRECT],
        to_str(SOCK_REDIRECT_NAME),
        &g_sock_redirect_xattr,
        BPF_SK_MSG_VERDICT,
        fds->map_fds[MESH_MAP_OPS_MAP].fd);
    ret += init_mesh_prog_pin_file(&fds->prog_fds[MESH_PROG_REDIRECT], pinprog_file_path[MESH_PROG_REDIRECT]);
    if (ret != SUCCESS)
        return FAILED;
    return SUCCESS;
}

int get_cgroup_root_fd(void)
{
    int cgroup_fd = ERROR;
    FILE *f = fopen("/proc/mounts", "r");
    if (f == NULL) {
        macli_log(ERR, "open /proc/mounts failed! search cgroup root path failed! errno:%d\n", errno);
        return ERROR;
    }

    struct mntent *mnt = NULL;
    while ((mnt = getmntent(f)) != NULL) {
        if (strcmp(mnt->mnt_type, "cgroup2") != 0)
            continue;
        cgroup_fd = open(mnt->mnt_dir, O_RDONLY);
        if (cgroup_fd < 0)
            macli_log(ERR, "cgroup:%s open failed! errno:%d\n", mnt->mnt_dir, errno);
        break;
    }
    if (fclose(f) != 0)
        macli_log(ERR, "can not close the file: /proc/mounts!\n");
    if (cgroup_fd < 0)
        macli_log(ERR, "maybe you need mount a cgroup2 root\n");
    return cgroup_fd;
}

int get_u32_num(const char *const src, __u32 *const ret)
{
    const int convert_base = 10;
    char tmp_buff[TMP_BUF_SIZE] = {0};
    unsigned long tmp = strtoul(src, NULL, convert_base);
    if (sprintf_s(tmp_buff, sizeof(tmp_buff), "%lu", tmp) < 0) {
        macli_log(ERR, "system sprintf string failed!\n");
        return FAILED;
    }
    if (strcmp(src, tmp_buff) != 0 || tmp > UINT32_MAX) {
        macli_log(ERR, "input num error, need a unsigned 32 bit num! input:%s\n", src);
        return FAILED;
    }
    *ret = (__u32)tmp;
    return SUCCESS;
}

int check_cidr(const char *const src, __u32 *const ip, __u32 *const mask)
{
    int ret = EOK;
    char tmp_buff[MAX_CIDR_LENGTH] = {0};
    if ((ret = strcpy_s(tmp_buff, sizeof(tmp_buff), src)) != EOK) {
        macli_log(ERR, "system copy string failed! errno:%d\n", ret);
        return FAILED;
    }
    char *ip_part = tmp_buff;
    char *p = strrchr(tmp_buff, '/');
    if (p == NULL)
        return FAILED;
    *p = '\0';
    char *mask_part = p + 1;

    const int max_mask = 32;
    struct in_addr dst;
    if (inet_pton(AF_INET, ip_part, (void *)&dst) <= 0)
        return FAILED;
    *ip = ntohl(dst.s_addr);
    if (get_u32_num(mask_part, mask) != SUCCESS || *mask > max_mask)
        return FAILED;

    return SUCCESS;
}

int check_port(const char *const src, __u32 *const begin_port, __u32 *const end_port)
{
    int ret = EOK;
    char tmp_buff[MAX_PORT_RANGE_LENGTH] = {0};
    if ((ret = strcpy_s(tmp_buff, sizeof(tmp_buff), src)) != EOK) {
        macli_log(ERR, "system copy string failed! errno:%d\n", ret);
        return FAILED;
    }
    // support 80-90
    // support 80
    char *num1 = tmp_buff;
    const __u32 max_port = 65535;
    char *p = strrchr(tmp_buff, '-');
    if (p == NULL) {
        if (get_u32_num(num1, begin_port) != SUCCESS)
            return FAILED;
        if (*begin_port > max_port) {
            macli_log(ERR, "ports over range!, max ports is %u, you input:%s\n", max_port, src);
            return FAILED;
        }
        *end_port = *begin_port;
    } else {
        *p = '\0';
        char *num2 = p + 1;
        if (get_u32_num(num1, begin_port) != SUCCESS)
            return FAILED;
        if (get_u32_num(num2, end_port) != SUCCESS)
            return FAILED;
        if (*begin_port > max_port || *end_port > max_port) {
            macli_log(ERR, "ports over range!, max ports is %u, you input:%s\n", max_port, src);
            return FAILED;
        }
        if (*begin_port > *end_port) {
            macli_log(ERR, "end ports large than begin ports! you input:%s\n", src);
            return FAILED;
        }
    }
    return SUCCESS;
}

int get_map_filter_rule(const struct mesh_map_info *const param_map_info, struct sock_param *const param_list)
{
    int key = 0;
    if (bpf_map_lookup_elem(param_map_info->fd, &key, param_list)) {
        macli_log(ERR, "look up dump param failed! errno:%d\n", errno);
        return FAILED;
    }
    return SUCCESS;
}
