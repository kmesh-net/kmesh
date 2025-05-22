// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <math.h>
#include "macli.h"

static const struct option g_chain_options[] = {
    {"ip", required_argument, NULL, 'i'},
    {"ports", required_argument, NULL, 'p'},
#if MDA_GID_UID_FILTER
    {"uid-owner", required_argument, NULL, 'u'},
    {"gid-owner", required_argument, NULL, 'g'},
#endif
    {"jump", required_argument, NULL, 'j'},
    {NULL}};

static void chain_usage(void)
{
    (void)printf("config file usage: chain {OPTIONS}\n");
    (void)printf("       OPTIONS: -i|--ip:        filter cidr:ip/mask\n");
    (void)printf("                -p|--ports:     filter ports,eg:15001-15006\n");
#if MDA_GID_UID_FILTER
    (void)printf("                -u|--uid-owner: filter uids,eg:1337\n");
    (void)printf("                -g|--gid-owner: filter gids,eg:1337\n");
#endif
    (void)printf("                -j|--jump:      RETURN or ACCEPT,eg:accept/return\n");
}

static int get_input_ip(const char *const src, struct input_filter_rule *const input_filter_rules)
{
    if (input_filter_rules->input_ip_num >= MAX_PARAM_LENGTH) {
        macli_log(ERR, "over the max cidrs set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    int ret = strcpy_s(input_filter_rules->input_ip[(input_filter_rules->input_ip_num)++], MAX_CIDR_LENGTH, src);
    if (ret == ERANGE_AND_RESET) {
        macli_log(ERR, "input cidr string too long!\n");
        return FAILED;
    } else if (ret != EOK) {
        macli_log(ERR, "get filter rules failed! errno:%d\n", ret);
        return FAILED;
    }
    return SUCCESS;
}

static int get_input_port(const char *const src, struct input_filter_rule *const input_filter_rules)
{
    if (input_filter_rules->input_port_num >= MAX_PARAM_LENGTH) {
        macli_log(ERR, "over the max ports set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    int ret =
        strcpy_s(input_filter_rules->input_port[(input_filter_rules->input_port_num)++], MAX_PORT_RANGE_LENGTH, src);
    if (ret == ERANGE_AND_RESET) {
        macli_log(ERR, "input port string is too long!\n");
        return FAILED;
    } else if (ret != EOK) {
        macli_log(ERR, "get filter rules failed! errno:%d\n", ret);
        return FAILED;
    }
    return SUCCESS;
}

static int set_cidr_filter_rule(struct input_cidr *const p, __u32 ipv4, __u32 mask)
{
    if (p->current_cidr_num + 1 > MAX_PARAM_LENGTH) {
        macli_log(
            ERR, "can not set accept ip rule, because the rule is too much! max rule num is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }

    p->cidrs[p->current_cidr_num].ip4 = ipv4;
    p->cidrs[p->current_cidr_num].mask =
        (__u32)(pow(MASK_BASE_NUM, MASK_LENGTH) - pow(MASK_BASE_NUM, MASK_LENGTH - mask));
    p->current_cidr_num++;
    macli_log(DEBUG, "add ip:%u, mask:%u to filter\n", ipv4, mask);
    return SUCCESS;
}

static int set_port_filter_rule(struct input_port *const p, __u32 begin_port, __u32 end_port)
{
    if (p->current_port_num + 1 > MAX_PARAM_LENGTH) {
        macli_log(
            ERR, "can not set accept ports rule, because the rule is too much! max rule num is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    p->ports[p->current_port_num].begin_port = begin_port;
    p->ports[p->current_port_num].end_port = end_port;
    p->current_port_num++;
    macli_log(DEBUG, "add beginport:%u, endport:%u to filter\n", begin_port, end_port);
    return SUCCESS;
}

static int init_cidr_param(
    struct sock_param *const filter_rules, const struct input_filter_rule *const input_filter_rules, bool is_accept)
{
    struct input_cidr *p = NULL;
    if (is_accept)
        p = &filter_rules->accept_cidrs;
    else
        p = &filter_rules->return_cidrs;

    for (int i = 0; i < input_filter_rules->input_ip_num; ++i) {
        __u32 ipv4 = 0;
        __u32 mask = 0;
        if (check_cidr(input_filter_rules->input_ip[i], &ipv4, &mask)) {
            macli_log(ERR, "check ipv4 failed! input cidrs is %s\n", input_filter_rules->input_ip[i]);
            return FAILED;
        }
        if (set_cidr_filter_rule(p, ipv4, mask) != SUCCESS)
            return FAILED;
    }
    return SUCCESS;
}

static int init_port_param(
    struct sock_param *const filter_rules, const struct input_filter_rule *const input_filter_rules, bool is_accept)
{
    struct input_port *p = NULL;
    if (is_accept)
        p = &filter_rules->accept_ports;
    else
        p = &filter_rules->return_ports;
    for (int i = 0; i < input_filter_rules->input_port_num; ++i) {
        __u32 begin_port = 0;
        __u32 end_port = 0;
        if (check_port(input_filter_rules->input_port[i], &begin_port, &end_port)) {
            macli_log(ERR, "check ports failed! input ports is %s\n", input_filter_rules->input_port[i]);
            return FAILED;
        }
        if (set_port_filter_rule(p, begin_port, end_port))
            return FAILED;
    }
    return SUCCESS;
}

#if MDA_GID_UID_FILTER
static int get_input_uid(const char *const src, struct input_filter_rule *const input_filter_rules)
{
    if (input_filter_rules->input_uid_num >= MAX_UID_GID_LENGTH) {
        macli_log(ERR, "over the max uids set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    __u32 tmp_uid;
    if (get_u32_num(src, &tmp_uid) != SUCCESS) {
        macli_log(ERR, "not a valid uids! you input:%s\n", src);
        return FAILED;
    }
    input_filter_rules->input_uid[(input_filter_rules->input_uid_num)++] = tmp_uid;

    return SUCCESS;
}

static int get_input_gid(const char *const src, struct input_filter_rule *const input_filter_rules)
{
    if (input_filter_rules->input_gid_num >= MAX_UID_GID_LENGTH) {
        macli_log(ERR, "over the max gids set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    __u32 tmp_gid;
    if (get_u32_num(src, &tmp_gid) != SUCCESS) {
        macli_log(ERR, "not a valid gids! you input:%s\n", src);
        return FAILED;
    }
    input_filter_rules->input_gid[(input_filter_rules->input_gid_num)++] = tmp_gid;

    return SUCCESS;
}

static int set_uid_filter_rule(struct input_uid *const p, __u32 input_uid)
{
    if (p->current_uid_num + 1 > MAX_PARAM_LENGTH) {
        macli_log(
            ERR, "can not set accept uids rule, because the rule is too much! max rule num is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    p->uids[p->current_uid_num] = input_uid;
    p->current_uid_num++;
    macli_log(DEBUG, "add uids:%u to filter\n", input_uid);
    return SUCCESS;
}

static int set_gid_filter_rule(struct input_gid *const p, __u32 input_gid)
{
    if (p->current_gid_num + 1 > MAX_PARAM_LENGTH) {
        macli_log(
            ERR, "can not set accept gids rule, because the rule is too much! max rule num is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    p->gids[p->current_gid_num] = input_gid;
    p->current_gid_num++;
    macli_log(DEBUG, "add gids:%u to accept filter\n", input_gid);
    return SUCCESS;
}

static int init_gid_param(
    struct sock_param *const filter_rules, const struct input_filter_rule *const input_filter_rules, bool is_accept)
{
    struct input_gid *p = NULL;
    if (is_accept)
        p = &filter_rules->accept_gids;
    else
        p = &filter_rules->return_gids;
    for (int i = 0; i < input_filter_rules->input_gid_num; ++i) {
        if (set_gid_filter_rule(p, input_filter_rules->input_gid[i]))
            return FAILED;
    }
    return SUCCESS;
}

static int init_uid_param(
    struct sock_param *const filter_rules, const struct input_filter_rule *const input_filter_rules, bool is_accept)
{
    struct input_uid *p = NULL;
    if (is_accept)
        p = &filter_rules->accept_uids;
    else
        p = &filter_rules->return_uids;
    for (int i = 0; i < input_filter_rules->input_uid_num; ++i) {
        if (set_uid_filter_rule(p, input_filter_rules->input_uid[i]))
            return FAILED;
    }
    return SUCCESS;
}
#endif

static int set_filter_rule(
    struct sock_param *const filter_rules, const struct input_filter_rule *const input_filter_rules, bool is_accept)
{
    macli_log(DEBUG, "begin set_filter_rule\n");
    if (init_cidr_param(filter_rules, input_filter_rules, is_accept) != SUCCESS)
        return FAILED;

    if (init_port_param(filter_rules, input_filter_rules, is_accept) != SUCCESS)
        return FAILED;

#if MDA_GID_UID_FILTER
    if (init_uid_param(filter_rules, input_filter_rules, is_accept) != SUCCESS)
        return FAILED;

    if (init_gid_param(filter_rules, input_filter_rules, is_accept) != SUCCESS)
        return FAILED;
#endif

    return SUCCESS;
}

static int
chain_get_opt(int argc, char *const *argv, struct input_filter_rule *const input_filter_rules, bool *is_accept)
{
    int opt;
    // To use getopt_long, optind must be set to 1
    optind = 1;
    while ((opt = getopt_long(argc, argv, "i:p:u:g:j:", g_chain_options, NULL)) >= 0) {
        switch (opt) {
        case 'i':
            if (get_input_ip(optarg, input_filter_rules) != SUCCESS)
                return FAILED;
            break;
        case 'p':
            if (get_input_port(optarg, input_filter_rules) != SUCCESS)
                return FAILED;
            break;
#if MDA_GID_UID_FILTER
        case 'u':
            if (get_input_uid(optarg, input_filter_rules) != SUCCESS)
                return FAILED;
            break;
        case 'g':
            if (get_input_gid(optarg, input_filter_rules) != SUCCESS)
                return FAILED;
            break;
#endif
        case 'j':
            if (strcmp("ACCEPT", optarg) == 0 || strcmp("accept", optarg) == 0) {
                *is_accept = true;
            } else if (strcmp("RETURN", optarg) == 0 || strcmp("return", optarg) == 0) {
                *is_accept = false;
            } else {
                macli_log(ERR, "-j need param 'ACCEPT' or 'RETURN'!\n");
                return FAILED;
            }
            break;
        case '?':
        default:
            chain_usage();
            return FAILED;
        }
    }
    if (optind != argc) {
        macli_log(ERR, "unknown param!\n");
        chain_usage();
        return FAILED;
    }
    return SUCCESS;
}

/*
 * do_chain:Use to parse the configuration lines in the configuration file,
 *		  check that the entered configuration file is correct, and fill
 *		  the data into the PARam save structure
 * param: argc,argv: Line of configuration parameters passed in
 *	   filter_rules: Save the parsed configuration structure
 *	   chain --ip xxxxx --port xxxx -j return
 * return: SUCCESS
 *		 FAILED
 */
int do_chain(int argc, char *const *argv, struct sock_param *const filter_rules)
{
    if (argc <= 1 || (strcmp("chain", argv[0]) != 0)) {
        chain_usage();
        return FAILED;
    }

    struct input_filter_rule input_filter_rules = {0};

    bool is_accept = true;
    // You need to save the content and add it to the filtering structure only when it is read as Accept or reject
    if (chain_get_opt(argc, argv, &input_filter_rules, &is_accept) != SUCCESS)
        return FAILED;

    if (set_filter_rule(filter_rules, &input_filter_rules, is_accept))
        return FAILED;

    return SUCCESS;
}
