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

#include <sys/stat.h>
#include <sys/resource.h>
#include "macli.h"
#include "log.h"
#define MAX_BUFSIZE 2048

static const struct option g_enable_options[] = {
    {"config", required_argument, NULL, 'c'}, {"help", no_argument, NULL, 'h'}, {NULL}};

static const struct option g_disable_options[] = {{"help", no_argument, NULL, 'h'}, {NULL}};

static int set_rlimit(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        macli_log(ERR, "setrlimit(RLIMIT_MEMLOCK) failed!, errno:%d\n", errno);
        return FAILED;
    }
    return SUCCESS;
}

static void del_sock_file(const struct mesh_service_info *const fds)
{
    for (unsigned int i = 0; i < MESH_PROG_NUM; ++i) {
        if (remove(fds->prog_fds[i].pin_file_path) && errno != ENOENT)
            macli_log(
                WARN,
                "delete the pinned file:%s failed! errno:%d, please delete manual\n",
                fds->prog_fds[i].pin_file_path,
                errno);
    }
    for (unsigned int i = 0; i < MESH_MAP_NUM; ++i) {
        if (remove(fds->map_fds[i].pin_file_path) && errno != ENOENT)
            macli_log(
                WARN,
                "delete the pinned file:%s failed! errno:%d, please delete manual\n",
                fds->map_fds[i].pin_file_path,
                errno);
    }
    if (remove(BPF_PIN_FOLDER) && errno != ENOENT)
        macli_log(WARN, "delete the pinned file:%s failed! errno:%d, please delete manual\n", BPF_PIN_FOLDER, errno);
}

void close_fds(int cgroup_fd, const struct mesh_service_info *const fds)
{
    for (unsigned int i = 0; i < MESH_PROG_NUM; ++i) {
        if (fds->prog_fds[i].fd > 0)
            (void)close(fds->prog_fds[i].fd);
    }
    for (unsigned int i = 0; i < MESH_MAP_NUM; ++i) {
        if (fds->map_fds[i].fd > 0)
            (void)close(fds->map_fds[i].fd);
    }
    (void)close(cgroup_fd);
    if (fds->prog_fds[MESH_PROG_REDIRECT].attach_fd != fds->map_fds[MESH_MAP_OPS_MAP].fd)
        (void)close(fds->prog_fds[MESH_PROG_REDIRECT].attach_fd);
}

static struct bpf_object *get_program_object(struct mesh_prog_info *const prog_info)
{
    if (access(prog_info->xattr->file, R_OK)) {
        macli_log(ERR, "object file miss! please reinstall the rpm package!\n");
        return NULL;
    }

    struct bpf_object *obj = bpf_object__open_xattr(prog_info->xattr);
    if (obj == NULL) {
        macli_log(ERR, "can not open bpf program, path:%s, errno:%d\n", prog_info->xattr->file, errno);
        return NULL;
    }
    return obj;
}

static int set_program_type(const struct mesh_prog_info *const prog_info, const struct bpf_object *const obj)
{
    enum bpf_prog_type prog_type = prog_info->xattr->prog_type;
    enum bpf_attach_type expected_attach_type = prog_info->attach_type;
    struct bpf_program *pos = bpf_program__next(NULL, obj);
    if (pos == NULL) {
        macli_log(ERR, "obj:%s not contain a ebpf program!\n", prog_info->xattr->file);
        return FAILED;
    }
    bpf_program__set_type(pos, prog_type);
    bpf_program__set_expected_attach_type(pos, expected_attach_type);
    return SUCCESS;
}

static int reuse_program_map(const struct mesh_service_info *const fds, const struct bpf_object *const obj)
{
    struct bpf_map *map = NULL;
    bpf_map__for_each(map, obj)
    {
        for (unsigned int i = 0; i < MESH_MAP_NUM; ++i) {
            if (strcmp(bpf_map__name(map), fds->map_fds[i].name))
                continue;
            if (bpf_map__reuse_fd(map, fds->map_fds[i].fd)) {
                macli_log(ERR, "map:%s reused failed! errno:%d\n", fds->map_fds[i].name, errno);
                return FAILED;
            }
        }
    }
    return SUCCESS;
}

static int pinned_program_file(const struct mesh_prog_info *const prog_info, struct bpf_object *const obj)
{
    struct bpf_program *prog = NULL;
    if (bpf_object__load(obj) != 0) {
        macli_log(ERR, "open bpf obj:%s failed! errno:%d\n", prog_info->xattr->file, errno);
        return FAILED;
    }
    prog = bpf_program__next(NULL, obj);
    if (!prog) {
        macli_log(ERR, "object file:%s doesn't contain any bpf program\n", prog_info->xattr->file);
        return FAILED;
    }

    int fd = bpf_program__fd(prog);
    if (fd < 0) {
        macli_log(ERR, "get program %s fd failed! errno:%d\n", prog_info->name, errno);
        return FAILED;
    }

    if (bpf_obj_pin(fd, prog_info->pin_file_path)) {
        macli_log(ERR, "pin file %s failed! errno:%d\n", prog_info->xattr->file, errno);
        return FAILED;
    }
    return SUCCESS;
}

static int create_program_and_pinned(struct mesh_prog_info *const prog_info, const struct mesh_service_info *const fds)
{
    struct bpf_object *obj = get_program_object(prog_info);
    if (obj == NULL)
        goto FAIL;
    if (set_program_type(prog_info, obj) != SUCCESS)
        goto FAIL;

    if (reuse_program_map(fds, obj) != SUCCESS)
        goto FAIL;

    if (pinned_program_file(prog_info, obj) != SUCCESS)
        goto FAIL;
    bpf_object__close(obj);
    return SUCCESS;
FAIL:
    bpf_object__close(obj);
    return FAILED;
}

static int create_map(struct mesh_service_info *const fds)
{
    for (unsigned int i = 0; i < MESH_MAP_NUM; ++i) {
        if (fds->map_fds[i].fd == -1) {
            fds->map_fds[i].fd = bpf_create_map_xattr(fds->map_fds[i].xattr);
            if (fds->map_fds[i].fd < 0) {
                macli_log(ERR, "create %s failed! errno:%d\n", fds->map_fds[i].name, errno);
                return FAILED;
            }
        }
        if (access(fds->map_fds[i].pin_file_path, W_OK) == 0)
            continue;
        if (bpf_obj_pin(fds->map_fds[i].fd, fds->map_fds[i].pin_file_path)) {
            macli_log(ERR, "pin bpf map file:%s failed! errno:%d\n", fds->map_fds[i].pin_file_path, errno);
            return FAILED;
        }
    }
    return SUCCESS;
}

static int load_program(struct mesh_service_info *const fds)
{
    for (unsigned int i = MESH_PROG_OPS; i < MESH_PROG_NUM; ++i) {
        if (fds->prog_fds[i].fd == -1) {
            if (create_program_and_pinned(&fds->prog_fds[i], fds) != SUCCESS)
                return FAILED;
            fds->prog_fds[i].fd = bpf_obj_get(fds->prog_fds[i].pin_file_path);
        }
        // redirect mount on map
        if (strcmp(fds->prog_fds[i].name, to_str(SOCK_REDIRECT_NAME)) == 0)
            fds->prog_fds[i].attach_fd = fds->map_fds[MESH_MAP_OPS_MAP].fd;
        if (access(fds->prog_fds[i].pin_file_path, W_OK) == 0)
            continue;
        if (bpf_obj_pin(fds->prog_fds[i].fd, fds->prog_fds[i].pin_file_path)) {
            macli_log(ERR, "pin file %s failed! errno:%d\n", fds->prog_fds[i].pin_file_path, errno);
            return FAILED;
        }
    }
    return SUCCESS;
}

static int attach_program(const struct mesh_service_info *const fds)
{
    unsigned int flags;
    for (int i = (int)MESH_PROG_NUM - 1; i >= 0; --i) {
        flags = 0;
        if (strcmp(fds->prog_fds[i].name, to_str(SOCK_OPS_NAME)) == 0)
            flags = BPF_F_ALLOW_MULTI;
        if (bpf_prog_attach(fds->prog_fds[i].fd, fds->prog_fds[i].attach_fd, fds->prog_fds[i].attach_type, flags)) {
            macli_log(ERR, "failed to attach %s, errno:%d\n", fds->prog_fds[i].pin_file_path, errno);
            return FAILED;
        }
    }
    return SUCCESS;
}

static int detach_program(const struct mesh_service_info *const fds)
{
    for (int i = (int)MESH_PROG_NUM - 1; i >= 0; --i) {
        // if prog fd == -1，If attach fd is -1, detach is not mounted
        if (fds->prog_fds[i].fd != -1 && fds->prog_fds[i].attach_fd != -1) {
            if (bpf_prog_detach2(fds->prog_fds[i].fd, fds->prog_fds[i].attach_fd, fds->prog_fds[i].attach_type)
                && errno != ENOENT) {
                macli_log(ERR, "failed to detach %s, errno:%d\n", fds->prog_fds[i].name, errno);
                return FAILED;
            }
        }
    }
    return SUCCESS;
}

static void enable_usage(void)
{
    (void)printf("usage: mdacore enable {OPTIONS}\n");
    (void)printf("       OPTIONS: -c|--config:       config path,eg:/etc/oncn-mda/oncn-mda.conf\n");
    (void)printf("       OPTIONS: -h|--help:         print usage\n");
}

static int enable_get_opt(int argc, char *const *argv, char *const config_path, bool *const is_help)
{
    int opt;
    while ((opt = getopt_long(argc, argv, "c:h", g_enable_options, NULL)) >= 0) {
        switch (opt) {
        case 'c':
            if (realpath(optarg, config_path) == NULL) {
                macli_log(ERR, "input config path %s error! errno:%d\n", optarg, errno);
                return FAILED;
            }
            break;
        case 'h':
            enable_usage();
            *is_help = true;
            break;
        case '?':
        default:
            enable_usage();
            return FAILED;
        }
    }
    if (optind != argc) {
        macli_log(ERR, "unknown param!\n");
        enable_usage();
        return FAILED;
    }
    return SUCCESS;
}

static void disable_usage(void)
{
    (void)printf("usage: mdacore disable\n");
    (void)printf("       OPTIONS: -h|--help:       print usage\n");
}

static int disable_get_opt(int argc, char *const *argv, bool *const is_help)
{
    int opt;
    while ((opt = getopt_long(argc, argv, "h", g_disable_options, NULL)) >= 0) {
        switch (opt) {
        case 'h':
            disable_usage();
            *is_help = true;
            break;
        case '?':
        default:
            disable_usage();
            return FAILED;
        }
    }
    if (optind != argc) {
        macli_log(ERR, "unknown param!\n");
        disable_usage();
    }
    return SUCCESS;
}

static int update_param_map(const struct sock_param *const filter_rules, const struct mesh_service_info *const fds)
{
    int key = 0;
    if (bpf_map_update_elem(fds->map_fds[MESH_MAP_OPS_PARAM_MAP].fd, &key, filter_rules, BPF_ANY)) {
        macli_log(ERR, "key:%d, errno:%d\n", key, errno);
        return FAILED;
    }
    return SUCCESS;
}

static int parser_arg(char *const buff, int buff_length, int *const chain_argc, char *chain_argv[])
{
    char *p = buff;
    bool is_new_string = true;
    for (; p - buff < buff_length; ++p) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            is_new_string = true;
            *p = '\0';
            continue;
        }
        if (*chain_argc == MAX_INPUT - 1) {
            macli_log(ERR, "Too many configuration items!\n");
            return FAILED;
        }
        if (is_new_string) {
            chain_argv[(*chain_argc)++] = p;
            is_new_string = false;
        }
    }
    return SUCCESS;
}

static void init_dump_param(struct dump_prarm *const filter_rules)
{
    filter_rules->current_cidr_num = 0;
    filter_rules->current_port_num = 0;
    filter_rules->switch_on = FALSE;
}

static int check_file_access(const char *const config_path)
{
    struct stat buf;
    if (lstat(config_path, &buf) < 0) {
        macli_log(ERR, "check config path %s failed!\n", config_path);
        return FAILED;
    }
    if (!S_ISREG(buf.st_mode)) {
        macli_log(ERR, "the config you input is not a text file!\n");
        return FAILED;
    }
    // Check whether configuration file permissions are unique to root
    if (((buf.st_mode) & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) != 0) {
        macli_log(ERR, "the config you input not unique to root, please modify permission of the config\n");
        return FAILED;
    }
    return SUCCESS;
}

static int read_chain_config(const char *const config_path, struct sock_param *const filter_rules)
{
    int ret;
    if (check_file_access(config_path) != SUCCESS)
        return FAILED;
    FILE *config_file = fopen(config_path, "r");
    if (config_file == NULL) {
        macli_log(ERR, "can not open the config file! path:%s, errno:%d\n", config_path, errno);
        return FAILED;
    }
    char buf[MAX_BUFSIZE] = {0};
    char buf_save[MAX_BUFSIZE] = {0};
    while (fgets(buf, sizeof(buf), config_file) != NULL) {
        // check is it begin with "#"
        char *p = buf;
        while (((p - buf) < MAX_BUFSIZE - 1) && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;
        // fgets guarantees the last char is '\0'
        if (*p == '#' || *p == '\0')
            continue;

        if ((ret = strcpy_s(buf_save, sizeof(buf_save), buf)) != EOK) {
            macli_log(ERR, "system copy string failed! errno:%d\n", ret);
            continue;
        }
        char *chain_argv[MAX_INPUT] = {0};
        int chain_argc = 0;
        if (parser_arg(buf, (int)strlen(buf), &chain_argc, chain_argv) != SUCCESS)
            goto err;
        if (do_chain(chain_argc, chain_argv, filter_rules) != SUCCESS) {
            macli_log(ERR, "error input param:%s\n", buf_save);
            goto err;
        }
    }

    if (fclose(config_file) != 0)
        macli_log(ERR, "close config file failed!\n");
    return SUCCESS;

err:
    if (fclose(config_file))
        macli_log(ERR, "close config file failed!\n");
    return FAILED;
}

static int enable_service(struct mesh_service_info *fds, const struct sock_param *const filter_rules)
{
    /*
     * start ServiceMesh acclerating
     * param: fds:ServiceMesh's map collection
     *	  filter_rules:
     * return: SUCCESS
     *		FAILED
     */
    if (update_param_map(filter_rules, fds) != SUCCESS) {
        macli_log(ERR, "update the param map failed!\n");
        return FAILED;
    }

    if (load_program(fds) != SUCCESS) {
        macli_log(ERR, "load program failed!\n");
        return FAILED;
    }

    if (attach_program(fds) != SUCCESS) {
        macli_log(ERR, "program attach cgroup2 failed!\n");
        return FAILED;
    }
    return SUCCESS;
}

static int create_accelerate_fold(void)
{
    /*
     * Create a place directory for pin files to be used for acceleration
     * param: NA
     * return SUCCESS
     *	   FAILED
     */
    if (access(BPF_PIN_FOLDER, W_OK) == 0)
        return SUCCESS;
    if (errno != ENOENT) {
        macli_log(ERR, "can not write the folder %s, errno:%d\n", BPF_PIN_FOLDER, errno);
        return FAILED;
    }
    if (mkdir(BPF_PIN_FOLDER, S_IRWXU)) {
        macli_log(ERR, "can not create the folder %s, errno:%d\n", BPF_PIN_FOLDER, errno);
        return FAILED;
    }
    return SUCCESS;
}

static int clean_proxy_map(const struct mesh_service_info *const fds)
{
    /*
     * Clear the remaining data in the Sock proxy map to preventing data residue
     * param: serviceMesh’s map prog infomation
     * return: SUCCESS
     *		FAILED
     */
    if (fds->map_fds[MESH_MAP_OPS_MAP].fd < 0)
        return SUCCESS;
    struct sock_key *prev_ey = NULL;
    struct sock_key key;
    while (bpf_map_get_next_key(fds->map_fds[MESH_MAP_OPS_PROXY_MAP].fd, prev_ey, &key) == 0) {
        prev_ey = &key;
        if (bpf_map_delete_elem(fds->map_fds[MESH_MAP_OPS_PROXY_MAP].fd, &key) && errno != ENOENT) {
            macli_log(ERR, "can not delete the key! errno:%d\n", errno);
            return FAILED;
        }
    }
    if (errno != ENOENT) {
        macli_log(ERR, "clean the map key failed! errno:%d\n", errno);
        return FAILED;
    }
    return SUCCESS;
}

static void reset_filter_rules(struct sock_param *const filter_rules, const struct sock_param *const old_param)
{
    filter_rules->dump_params.switch_on = (*old_param).dump_params.switch_on;
    filter_rules->dump_params.current_cidr_num = (*old_param).dump_params.current_cidr_num;
    filter_rules->dump_params.current_port_num = (*old_param).dump_params.current_port_num;
    for (int i = 0; i < (*old_param).dump_params.current_cidr_num; ++i) {
        filter_rules->dump_params.dump_cidr[i].ip4 = (*old_param).dump_params.dump_cidr[i].ip4;
        filter_rules->dump_params.dump_cidr[i].mask = (*old_param).dump_params.dump_cidr[i].mask;
    }
    for (int i = 0; i < (*old_param).dump_params.current_port_num; ++i) {
        filter_rules->dump_params.dump_port[i].begin_port = (*old_param).dump_params.dump_port[i].begin_port;
        filter_rules->dump_params.dump_port[i].end_port = (*old_param).dump_params.dump_port[i].end_port;
    }
}

static int reset_param_map(struct sock_param *const filter_rules, const struct mesh_service_info *const fds)
{
    struct sock_param old_param;
    if (get_map_filter_rule(&fds->map_fds[MESH_MAP_OPS_PARAM_MAP], &old_param) != SUCCESS)
        return FAILED;
    reset_filter_rules(filter_rules, &old_param);
    if (update_param_map(filter_rules, fds) != SUCCESS)
        return FAILED;
    return SUCCESS;
}

int do_enable(int argc, char *const *argv)
{
    /*
     * start mesh accelerating
     * param: -c configfile
     * return: SUCCESS
     *		FAILED
     */
    bool is_help = false;
    char config_path[PATH_MAX] = {0};
    struct sock_param filter_rules = {0};
    struct mesh_service_info fds = {0};
    int ret;

    if (set_rlimit() != SUCCESS)
        return FAILED;

    if ((ret = strcpy_s(config_path, PATH_MAX, CONFIGFILE_PATH)) != EOK) {
        macli_log(ERR, "system copy string failed! errno:%d\n", ret);
        return FAILED;
    }

    if (enable_get_opt(argc, argv, config_path, &is_help) != SUCCESS)
        return FAILED;

    if (is_help)
        return SUCCESS;

    int cgroup2_fd = get_cgroup_root_fd();
    if (cgroup2_fd < 0)
        goto FINISH;

    // Read the configuration file and put the data into the map
    if (read_chain_config(config_path, &filter_rules) != SUCCESS)
        goto CLOSE_PINNED_FD;

    if (init_fds(&fds, cgroup2_fd) != SUCCESS)
        goto CLOSE_PINNED_FD;

    if (check_accelerating_on(&fds) == TRUE) {
        macli_log(INFO, "mesh service is enabled!\n");
        if (reset_param_map(&filter_rules, &fds) != SUCCESS) {
            macli_log(ERR, "reset mesh param failed!\n");
            goto CLOSE_PINNED_FD;
        }
        goto ENABLE_SUCCESS;
    }
    if (create_accelerate_fold() != SUCCESS)
        goto DELETE_FILE;
    if (create_map(&fds) != SUCCESS)
        goto DELETE_FILE;

    init_dump_param(&filter_rules.dump_params);

    if (enable_service(&fds, &filter_rules) != SUCCESS)
        goto DETACH;

ENABLE_SUCCESS:
    close_fds(cgroup2_fd, &fds);
    macli_log(INFO, "enable serviceMesh accelerating success!\n");
    return SUCCESS;
DETACH:
    (void)detach_program(&fds);
DELETE_FILE:
    del_sock_file(&fds);
CLOSE_PINNED_FD:
    close_fds(cgroup2_fd, &fds);
FINISH:
    macli_log(ERR, "enable serviceMesh accelerating failed!\n");
    return FAILED;
}

int do_disable(int argc, char *const *argv)
{
    int cgroup2_fd;
    bool is_help = false;
    if (disable_get_opt(argc, argv, &is_help))
        return FAILED;

    if (is_help)
        return SUCCESS;

    cgroup2_fd = get_cgroup_root_fd();
    if (cgroup2_fd < 0) {
        macli_log(ERR, "disable serviceMesh accelerating failed!\n");
        return FAILED;
    }

    struct mesh_service_info fds;
    if (init_fds(&fds, cgroup2_fd) != SUCCESS)
        goto CLOSE_PINNED_FD;

    if (detach_program(&fds) != SUCCESS)
        goto CLOSE_PINNED_FD;
    // clean proxy map data
    if (clean_proxy_map(&fds) != SUCCESS)
        goto CLOSE_PINNED_FD;
    close_fds(cgroup2_fd, &fds);
    del_sock_file(&fds);
    macli_log(INFO, "disable serviceMesh accelerating success!\n");
    return SUCCESS;
CLOSE_PINNED_FD:
    close_fds(cgroup2_fd, &fds);
    del_sock_file(&fds);
    macli_log(ERR, "disable serviceMesh accelerating failed!\n");
    return FAILED;
}
