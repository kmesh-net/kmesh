// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <sys/time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <protobuf-c/protobuf-c.h>

#include "deserialization_to_bpf_map.h"
#include "../../config/kmesh_marcos_def.h"
#include "../include/inner_map_defs.h"

#define PRINTF(fmt, args...)                                                                                           \
    do {                                                                                                               \
        struct timeval tv;                                                                                             \
        struct timezone tz;                                                                                            \
        gettimeofday(&tv, &tz);                                                                                        \
        long ms = tv.tv_usec / 1000;                                                                                   \
        char time_str[30];                                                                                             \
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));                              \
        printf("%s.%03ld " fmt "\n", time_str, ms, ##args);                                                            \
        fflush(stdout);                                                                                                \
    } while (0)

#define LOG_ERR(fmt, args...)  PRINTF("[ERROR] " fmt, ##args)
#define LOG_WARN(fmt, args...) PRINTF("[WARN] " fmt, ##args)
#define LOG_INFO(fmt, args...) PRINTF("[INFO] " fmt, ##args)

struct op_context {
    void *key;
    void *value;
    int curr_fd;
    struct bpf_map_info *curr_info;
    char *map_object;
    const ProtobufCMessageDescriptor *desc;
};

#define init_op_context(context, k, v, desc, fd, m_info)                                                               \
    do {                                                                                                               \
        (context).key = (k);                                                                                           \
        (context).value = (v);                                                                                         \
        (context).desc = (desc);                                                                                       \
        (context).curr_info = (m_info);                                                                                \
        (context).curr_fd = (fd);                                                                                      \
    } while (0)

#define append_new_node(elem_list_head, curr_elem_list_node, new_node)                                                 \
    do {                                                                                                               \
        if (curr_elem_list_node == NULL) {                                                                             \
            curr_elem_list_node = elem_list_head = new_node;                                                           \
        } else {                                                                                                       \
            curr_elem_list_node->next = new_node;                                                                      \
            curr_elem_list_node = new_node;                                                                            \
        }                                                                                                              \
    } while (0)

struct inner_map_stat {
    int map_fd;
    unsigned int used : 1;
    unsigned int allocated : 1;
    unsigned int resv : 30;
};

#define BITMAP_SIZE (MAP_MAX_ENTRIES / 8)
struct map_mng {
    int inner_fds[MAP_TYPE_MAX];
    struct bpf_map_info inner_infos[MAP_TYPE_MAX];
    unsigned char used_bitmap[MAP_TYPE_MAX][BITMAP_SIZE];
    unsigned int start_pos[MAP_TYPE_MAX];
};

struct map_mng g_map_mng = {0};

static int update_bpf_map(struct op_context *ctx);
static void *create_struct(struct op_context *ctx, int *err);
static int del_bpf_map(struct op_context *ctx);
static int free_outter_map_entry(struct op_context *ctx, unsigned int *outer_key);

static int normalize_key(struct op_context *ctx, void *key, const char *map_name)
{
    ctx->key = calloc(1, ctx->curr_info->key_size);
    if (!ctx->key)
        return -errno;

    if (!map_name)
        return -errno;

    if (!strncmp(map_name, "Listener", strlen(map_name)))
        memcpy_s(ctx->key, ctx->curr_info->key_size, key, ctx->curr_info->key_size);
    else
        strncpy(ctx->key, key, ctx->curr_info->key_size);

    return 0;
}

static inline int selected_oneof_field(void *value, const ProtobufCFieldDescriptor *field)
{
    unsigned int n = *(unsigned int *)((char *)value + field->quantifier_offset);

    if ((field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) && field->id != n)
        return 0;

    return 1;
}

static inline int valid_field_value(void *value, const ProtobufCFieldDescriptor *field)
{
    unsigned int val = *(unsigned int *)((char *)value + field->offset);

    if (val == 0) {
        switch (field->type) {
        case PROTOBUF_C_TYPE_MESSAGE:
        case PROTOBUF_C_TYPE_STRING:
            return 0;
        default:
            break;
        }

        switch (field->label) {
        case PROTOBUF_C_LABEL_REPEATED:
            return 0;
        default:
            break;
        }
    }

    return 1;
}

static inline size_t sizeof_elt_in_repeated_array(ProtobufCType type)
{
    switch (type) {
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
    case PROTOBUF_C_TYPE_FIXED32:
    case PROTOBUF_C_TYPE_FLOAT:
    case PROTOBUF_C_TYPE_ENUM:
        return 4;
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_FIXED64:
    case PROTOBUF_C_TYPE_DOUBLE:
        return 8;
    case PROTOBUF_C_TYPE_BOOL:
        return sizeof(protobuf_c_boolean);
    case PROTOBUF_C_TYPE_STRING:
    case PROTOBUF_C_TYPE_MESSAGE:
        return sizeof(void *);
    case PROTOBUF_C_TYPE_BYTES:
        return sizeof(ProtobufCBinaryData);
    default:
        break;
    }

    return 0;
}

static inline int valid_outer_key(struct op_context *ctx, unsigned int outer_key)
{
    unsigned char type = MAP_GET_TYPE(outer_key);
    unsigned int inner_idx = MAP_GET_INDEX(outer_key);
    if (type >= MAP_TYPE_MAX || inner_idx >= MAP_MAX_ENTRIES)
        return 0;

    return 1;
}

static void free_elem(void *ptr)
{
    if ((uintptr_t)ptr < UINT32_MAX)
        return;

    free(ptr);
}

static void free_keys(struct op_context *ctx, void *keys, int n)
{
    int i;
    unsigned int key;
    for (i = 0; i < n; i++) {
        key = *((uintptr_t *)keys + i);
        if (!key)
            return;

        free_outter_map_entry(ctx, &key);
    }
}

static int get_map_id(const char *name, unsigned int *id)
{
    char *map_id;
    char *ptr = NULL;

    map_id = getenv(name);
    if (!map_id) {
        LOG_ERR("%s is not set, errno:%d", name, errno);
        return -EINVAL;
    }
    *id = (unsigned int)strtol(map_id, &ptr, 10);
    return 0;
}

static int get_map_fd_info(unsigned int id, int *map_fd, struct bpf_map_info *info)
{
    int ret;
    __u32 map_info_len;

    *map_fd = bpf_map_get_fd_by_id(id);
    if (*map_fd < 0)
        return *map_fd;

    map_info_len = sizeof(*info);
    ret = bpf_obj_get_info_by_fd(*map_fd, info, &map_info_len);
    return ret;
}

static int free_outter_map_entry(struct op_context *ctx, unsigned int *outer_key)
{
    unsigned char type = MAP_GET_TYPE(*outer_key);
    unsigned int inner_idx = MAP_GET_INDEX(*outer_key);

    if (type >= MAP_TYPE_MAX || inner_idx >= MAP_MAX_ENTRIES)
        return -1;

    CLEAR_BIT(g_map_mng.used_bitmap[type], inner_idx);
    *outer_key = 0;
    return 0;
}

static unsigned int bitmap_find_first_clear(unsigned char *bitmap, unsigned int *start_pos, unsigned int bitmap_size)
{
    unsigned int i = *start_pos, j;
    unsigned char bmp;

    if (i && IS_SET(bitmap, i) == 0) {
        *start_pos = ((i + 1) % bitmap_size) ?: 1;
        return i;
    }

    for (i = 0; i < (bitmap_size / 8); i++) {
        bmp = bitmap[i];
        for (j = 0; j < 8; j++) {
            if (i == 0 && j == 0)
                continue;
            if (!(bmp & (1U << j))) {
                *start_pos = ((i * 8 + j + 1) % bitmap_size) ?: 1;
                return (i * 8 + j);
            }
        }
    }
    return -1;
}

static unsigned int alloc_outer_key(struct op_context *ctx, int size)
{
    unsigned int i, j;
    if (size <= 0) {
        LOG_ERR("Invalid size:%d", size);
        return -1;
    }

    for (i = 0; i < MAP_TYPE_MAX; i++) {
        if (size > g_map_mng.inner_infos[i].value_size)
            continue;

        j = bitmap_find_first_clear(&g_map_mng.used_bitmap[i][0], &g_map_mng.start_pos[i], MAP_MAX_ENTRIES);
        if (j > 0 && j < MAP_MAX_ENTRIES)
            break;
    }

    if (i == MAP_TYPE_MAX) {
        LOG_ERR("alloc_map_in_map_entry failed, size:%d", size);
        return -1;
    }

    SET_BIT(g_map_mng.used_bitmap[i], j);
    return MAP_GEN_OUTER_KEY(i, j);
}

static int
outer_key_to_inner_map_index(unsigned int outer_key, int *inner_fd, struct bpf_map_info **map_info, int *inner_idx)
{
    unsigned char type = MAP_GET_TYPE(outer_key);
    unsigned int idx = MAP_GET_INDEX(outer_key);

    if (type >= MAP_TYPE_MAX || idx >= MAP_MAX_ENTRIES) {
        LOG_ERR("outer_key_to_inner_map_index outer_key(%u) invalid.", outer_key);
        return -1;
    }

    *inner_idx = idx;
    *inner_fd = g_map_mng.inner_fds[type];
    if (map_info)
        *map_info = &g_map_mng.inner_infos[type];
    return 0;
}

static int copy_byte_field_to_map(struct op_context *ctx, unsigned int outer_key, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    struct bpf_map_info *inner_info;

    struct ProtobufCBinaryData *bytes = (struct ProtobufCBinaryData *)((char *)ctx->value + field->offset);
    unsigned char *save_value = bytes->data;
    *(uintptr_t *)&bytes->data = (size_t)outer_key;

    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret)
        return ret;

    ret = outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    memcpy_s(ctx->map_object, inner_info->value_size, save_value, bytes->len);
    ret = bpf_map_update_elem(inner_fd, &key, ctx->map_object, BPF_ANY);
    return ret;
}

static int copy_sfield_to_map(struct op_context *ctx, unsigned int outer_key, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    struct bpf_map_info *inner_info;
    char **value = (char **)((char *)ctx->value + field->offset);
    char *save_value = *value;

    *(uintptr_t *)value = (size_t)outer_key;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        LOG_ERR("copy_sfield_to_map bpf_map_update_elem failed, ret:%d ERRNO:%d", ret, errno);
        return ret;
    }

    ret = outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    strcpy_s(ctx->map_object, inner_info->value_size, save_value);
    ret = bpf_map_update_elem(inner_fd, &key, ctx->map_object, BPF_ANY);
    return ret;
}

static int copy_msg_field_to_map(struct op_context *ctx, unsigned int outer_key, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    struct bpf_map_info *inner_info = NULL;
    void **value = (void **)((char *)ctx->value + field->offset);
    void *msg = *value;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc = ((ProtobufCMessage *)msg)->descriptor;

    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
        return -EINVAL;
    }

    *(uintptr_t *)value = (size_t)outer_key;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        LOG_ERR("copy_msg_field_to_map bpf_map_update_elem failed, ret:%d ERRNO:%d", ret, errno);
        return ret;
    }

    ret = outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&key;
    new_ctx.value = msg;
    new_ctx.curr_info = inner_info;
    new_ctx.desc = desc;
    return update_bpf_map(&new_ctx);
}

static int get_string_field_size(const ProtobufCFieldDescriptor *field, char *str)
{
    int real_len;
    if (!str)
        return -1;

    real_len = strlen(str) + 1;
    if (real_len > MAP_VAL_STR_SIZE) {
        LOG_ERR(
            "fieldName:%s, id:%d, len:%d over str_max_len(%d).", field->name, field->id, real_len, MAP_VAL_STR_SIZE);
        return -1;
    }
    return MAP_VAL_STR_SIZE;
}

static int get_msg_field_size(const ProtobufCFieldDescriptor *field)
{
    return ((ProtobufCMessageDescriptor *)(field->descriptor))->sizeof_message;
}

static int get_binary_field_size(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    struct ProtobufCBinaryData *bytes = (struct ProtobufCBinaryData *)((char *)ctx->value + field->offset);
    if (bytes->len > MAP_VAL_BINARY_SIZE)
        return -1;
    return MAP_VAL_BINARY_SIZE;
}

static int get_struct_field_size(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    char *value = NULL;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        return get_msg_field_size(field);

    case PROTOBUF_C_TYPE_STRING:
        value = *(char **)((char *)ctx->value + field->offset);
        return get_string_field_size(field, value);

    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_ENUM:
    case PROTOBUF_C_TYPE_BYTES:
        return get_binary_field_size(ctx, field);

    default:
        return -1;
    }
}

static int field_handle(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    unsigned int key;

    if (field->type != PROTOBUF_C_TYPE_MESSAGE && field->type != PROTOBUF_C_TYPE_STRING
        && field->type != PROTOBUF_C_TYPE_BYTES)
        return 0;

    key = alloc_outer_key(ctx, get_struct_field_size(ctx, field));
    if (key < 0)
        return key;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        ret = copy_msg_field_to_map(ctx, key, field);
        break;
    case PROTOBUF_C_TYPE_STRING:
        ret = copy_sfield_to_map(ctx, key, field);
        break;
    case PROTOBUF_C_TYPE_BYTES:
        ret = copy_byte_field_to_map(ctx, key, field);
        break;
    default:
        return 0;
    }

    if (ret)
        free_outter_map_entry(ctx, &key);
    return ret;
}

static int copy_indirect_data_to_map(struct op_context *ctx, unsigned int outer_key, void *value, ProtobufCType type)
{
    int ret = 0;
    int inner_fd, key = 0;
    struct op_context new_ctx;
    struct bpf_map_info *inner_info;
    const ProtobufCMessageDescriptor *desc;

    ret = outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    switch (type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.value = value;
        new_ctx.curr_info = inner_info;

        desc = ((ProtobufCMessage *)value)->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            return -EINVAL;
        }

        new_ctx.desc = desc;
        ret = update_bpf_map(&new_ctx);
        break;
    case PROTOBUF_C_TYPE_STRING:
        strcpy_s(ctx->map_object, inner_info->value_size, (char *)value);
        ret = bpf_map_update_elem(inner_fd, &key, ctx->map_object, BPF_ANY);
        break;
    default:
        break;
    }

    return ret;
}

static bool indirect_data_type(ProtobufCType type)
{
    switch (type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        return true;
    default:
        return false;
    }
}

static int repeat_field_handle(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret, ret1;
    unsigned int i;
    int field_len;
    int inner_fd, key = 0;
    unsigned int outer_key;
    struct bpf_map_info *inner_info = NULL;
    void *n = ((char *)ctx->value) + field->quantifier_offset;
    void ***value = (void ***)((char *)ctx->value + field->offset);
    void **origin_value = *value;
    char *map_object;

    outer_key = alloc_outer_key(ctx, MAP_VAL_REPEAT_SIZE);
    if (outer_key < 0)
        return outer_key;
    *(uintptr_t *)value = (size_t)outer_key;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        LOG_ERR("repeat_field_handle bpf_map_update_elem failed, ret:%d ERRNO:%d", ret, errno);
        free_outter_map_entry(ctx, &outer_key);
        return ret;
    }

    ret = outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    map_object = calloc(1, inner_info->value_size);
    if (!map_object) {
        return -ENOMEM;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        for (i = 0; i < *(unsigned int *)n; i++) {
            if (field->type == PROTOBUF_C_TYPE_STRING)
                field_len = get_string_field_size(field, (char *)origin_value[i]);
            else
                field_len = get_msg_field_size(field);
            outer_key = alloc_outer_key(ctx, field_len);
            if (outer_key < 0)
                goto end;

            *((uintptr_t *)map_object + i) = (size_t)outer_key;
            ret = copy_indirect_data_to_map(ctx, outer_key, origin_value[i], field->type);
            if (ret)
                goto end;
        }
        break;
    default:
        memcpy_s(
            map_object,
            inner_info->value_size,
            (void *)origin_value,
            *(size_t *)n * sizeof_elt_in_repeated_array(field->type));
        break;
    }

end:
    ret1 = bpf_map_update_elem(inner_fd, &key, map_object, BPF_ANY);
    if (ret1) {
        ret = ret1;
        if (indirect_data_type(field->type))
            free_keys(ctx, map_object, *(size_t *)n);
    }

    free(map_object);
    return ret;
}

static int update_bpf_map(struct op_context *ctx)
{
    int ret;
    unsigned int i;
    void *temp_val;
    const ProtobufCMessageDescriptor *desc = ctx->desc;

    if (desc->sizeof_message > ctx->curr_info->value_size) {
        LOG_ERR("map entry size is too small");
        return -EINVAL;
    }

    temp_val = malloc(ctx->curr_info->value_size);
    if (!temp_val)
        return -ENOMEM;

    memcpy_s(temp_val, ctx->curr_info->value_size, ctx->value, desc->sizeof_message);
    ctx->value = temp_val;

    for (i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *field = desc->fields + i;

        if (!selected_oneof_field(ctx->value, field) || !valid_field_value(ctx->value, field))
            continue;

        switch (field->label) {
        case PROTOBUF_C_LABEL_REPEATED:
            ret = repeat_field_handle(ctx, field);
            break;
        default:
            ret = field_handle(ctx, field);
            break;
        }

        if (ret) {
            LOG_INFO(
                "desc.name:%s field[%d - %s] handle failed:%d, errno:%d",
                desc->short_name,
                i,
                desc->fields[i].name,
                ret,
                errno);
            free(temp_val);
            return ret;
        }
    }

    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    free(temp_val);
    return ret;
}

int deserial_update_elem(void *key, void *value)
{
    int ret;
    const char *map_name = NULL;
    struct op_context context = {.map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info info = {0};
    int map_fd = 0;
    unsigned int id;

    if (!key || !value)
        return -EINVAL;

    desc = ((ProtobufCMessage *)value)->descriptor;
    if (desc && desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        map_name = desc->short_name;

    ret = get_map_id(map_name, &id);
    if (ret)
        return ret;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d, errno:%d", id, errno);
        return ret;
    }

    if (!map_name) {
        ret = bpf_map_update_elem(map_fd, key, value, BPF_ANY);
        goto end;
    }

    deserial_delete_elem(key, desc);

    init_op_context(context, key, value, desc, map_fd, &info);

    context.map_object = calloc(1, g_map_mng.inner_infos[MAP_TYPE_MAX - 1].value_size);
    if (context.map_object == NULL) {
        ret = -errno;
        goto end;
    }

    normalize_key(&context, key, map_name);

    ret = update_bpf_map(&context);
    if (ret)
        deserial_delete_elem(key, desc);

end:
    if (context.key != NULL)
        free(context.key);
    if (context.map_object != NULL)
        free(context.map_object);
    if (map_fd > 0)
        close(map_fd);
    return ret;
}

static int query_string_field(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int inner_fd, key;
    void *string;
    struct bpf_map_info *map_info = NULL;
    void *outer_key = (void *)((char *)ctx->value + field->offset);

    ret = outer_key_to_inner_map_index(*(unsigned int *)outer_key, &inner_fd, &map_info, &key);
    if (ret)
        return ret;

    string = calloc(1, map_info->value_size);
    if (!string) {
        return -ENOMEM;
    }

    (*(uintptr_t *)outer_key) = (uintptr_t)string;
    ret = bpf_map_lookup_elem(inner_fd, &key, string);
    return ret;
}

static int query_message_field(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    void *message;
    struct op_context new_ctx;
    struct bpf_map_info *map_info = NULL;
    const ProtobufCMessageDescriptor *desc;
    uintptr_t *outer_key = (uintptr_t *)((char *)ctx->value + field->offset);

    ret = outer_key_to_inner_map_index(*(unsigned int *)outer_key, &inner_fd, &map_info, &key);
    if (ret)
        return ret;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&key;
    new_ctx.curr_info = map_info;

    desc = (ProtobufCMessageDescriptor *)field->descriptor;
    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
        return -EINVAL;
    }

    new_ctx.desc = desc;
    message = create_struct(&new_ctx, &ret);
    *outer_key = (uintptr_t)message;
    return ret;
}

static int field_query(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        return query_message_field(ctx, field);
    case PROTOBUF_C_TYPE_STRING:
        return query_string_field(ctx, field);
    default:
        break;
    }

    return 0;
}

static void *
create_indirect_struct(struct op_context *ctx, unsigned long outer_key, const ProtobufCFieldDescriptor *field, int *err)
{
    int ret, inner_fd, key = 0;
    void *value = NULL;
    struct op_context new_ctx;
    struct bpf_map_info *map_info = NULL;
    const ProtobufCMessageDescriptor *desc;

    ret = outer_key_to_inner_map_index((unsigned int)outer_key, &inner_fd, &map_info, &key);
    if (ret)
        return NULL;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.curr_info = map_info;

        desc = (ProtobufCMessageDescriptor *)field->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            *err = -EINVAL;
            return NULL;
        }

        new_ctx.desc = desc;
        value = create_struct(&new_ctx, err);
        return value;
    default:
        value = calloc(1, map_info->value_size);
        if (!value) {
            *err = -ENOMEM;
            return NULL;
        }

        *err = bpf_map_lookup_elem(inner_fd, &key, value);
        if (*err < 0) {
            return value;
        }
        break;
    }

    *err = 0;
    return value;
}

static int repeat_field_query(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    void *array;
    unsigned int i;
    struct bpf_map_info *map_info = NULL;
    void *n = ((char *)ctx->value) + field->quantifier_offset;
    uintptr_t *outer_key = (uintptr_t *)((char *)ctx->value + field->offset);

    ret = outer_key_to_inner_map_index(*(unsigned int *)outer_key, &inner_fd, &map_info, &key);
    if (ret)
        return ret;

    array = calloc(1, map_info->value_size);
    if (!array) {
        return -ENOMEM;
    }

    *outer_key = (uintptr_t)array;
    ret = bpf_map_lookup_elem(inner_fd, &key, array);
    if (ret < 0) {
        return ret;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        for (i = 0; i < *(unsigned int *)n; i++) {
            outer_key = (uintptr_t *)array + i;
            *outer_key = (uintptr_t)create_indirect_struct(ctx, *outer_key, field, &ret);
            if (ret)
                break;
        }
        break;
    default:
        break;
    }

    return ret;
}

void deserial_free_elem_list(struct element_list_node *head)
{
    while (head != NULL) {
        struct element_list_node *n = head;
        deserial_free_elem(n->elem);
        head = n->next;
        free(n);
    }
}

static void *create_struct_list(struct op_context *ctx, int *err)
{
    void *prev_key = NULL;
    void *value;
    struct element_list_node *elem_list_head = NULL;
    struct element_list_node *curr_elem_list_node = NULL;

    *err = 0;
    ctx->key = calloc(1, ctx->curr_info->key_size);
    while (!bpf_map_get_next_key(ctx->curr_fd, prev_key, ctx->key)) {
        prev_key = ctx->key;

        value = create_struct(ctx, err);
        if (*err) {
            LOG_ERR("create_struct failed, err = %d", err);
            break;
        }

        if (value == NULL) {
            continue;
        }

        struct element_list_node *new_node = (struct element_list_node *)calloc(1, sizeof(struct element_list_node));
        if (!new_node) {
            *err = -1;
            break;
        }

        new_node->elem = value;
        new_node->next = NULL;
        append_new_node(elem_list_head, curr_elem_list_node, new_node);
    }
    if (*err) {
        deserial_free_elem_list(elem_list_head);
        return NULL;
    }
    return elem_list_head;
}

static void *create_struct(struct op_context *ctx, int *err)
{
    void *value;
    int ret;
    unsigned int i;
    const ProtobufCMessageDescriptor *desc = ctx->desc;

    *err = 0;

    if (desc->sizeof_message > ctx->curr_info->value_size) {
        LOG_ERR("map entry size is too small");
        return NULL;
    }

    value = calloc(1, ctx->curr_info->value_size);
    if (!value)
        return value;

    ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, value);
    if (ret < 0) {
        free(value);
        return NULL;
    }

    ctx->value = value;
    ((ProtobufCMessage *)value)->descriptor = desc;
    for (i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *field = desc->fields + i;

        if (!selected_oneof_field(ctx->value, field) || !valid_field_value(ctx->value, field))
            continue;

        switch (field->label) {
        case PROTOBUF_C_LABEL_REPEATED:
            ret = repeat_field_query(ctx, field);
            break;
        default:
            ret = field_query(ctx, field);
            break;
        }

        if (ret) {
            LOG_INFO("field[%d] query fail", i);
            *err = 1;
            break;
        }
    }

    if (*err) {
        deserial_free_elem(value);
        return NULL;
    }

    return value;
}

struct element_list_node *deserial_lookup_all_elems(const void *msg_desciptor)
{
    int ret, err;
    struct element_list_node *value_list_head = NULL;
    const char *map_name = NULL;
    struct op_context context = {.map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info info = {0};
    int map_fd;
    unsigned int id;

    if (msg_desciptor == NULL)
        return NULL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return NULL;

    map_name = desc->short_name;
    ret = get_map_id(map_name, &id);
    if (ret)
        return NULL;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d", id);
        return NULL;
    }

    init_op_context(context, NULL, NULL, desc, map_fd, &info);

    value_list_head = create_struct_list(&context, &err);
    if (err != 0) {
        LOG_ERR("create_struct_list failed, err = %d", err);
    }

    if (context.key != NULL)
        free(context.key);
    if (map_fd > 0)
        close(map_fd);
    return value_list_head;
}

void *deserial_lookup_elem(void *key, const void *msg_desciptor)
{
    int ret, err;
    void *value = NULL;
    const char *map_name = NULL;
    struct op_context context;
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info info = {0};
    int map_fd;
    unsigned int id;

    if (msg_desciptor == NULL || key == NULL)
        return NULL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return NULL;

    map_name = desc->short_name;
    ret = get_map_id(map_name, &id);
    if (ret)
        return NULL;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d", id);
        return NULL;
    }

    init_op_context(context, key, NULL, desc, map_fd, &info);

    normalize_key(&context, key, map_name);
    value = create_struct(&context, &err);
    if (err != 0) {
        LOG_ERR("create_struct failed, err = %d", err);
    }

    if (context.key != NULL)
        free(context.key);
    if (map_fd > 0)
        close(map_fd);
    return value;
}

static int indirect_field_del(struct op_context *ctx, unsigned int outer_key, const ProtobufCFieldDescriptor *field)
{
    char *map_object = NULL;
    int inner_fd, key = 0;
    struct op_context new_ctx;
    struct bpf_map_info *inner_info;
    const ProtobufCMessageDescriptor *desc;

    if (!valid_outer_key(ctx, outer_key))
        return -EINVAL;

    outer_key_to_inner_map_index(outer_key, &inner_fd, &inner_info, &key);
    free_outter_map_entry(ctx, &outer_key);

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        desc = (ProtobufCMessageDescriptor *)field->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            break;
        }

        map_object = malloc(inner_info->value_size);
        if (!map_object) {
            LOG_WARN("indirect_field_del malloc failed:%d", errno);
            break;
        }

        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.curr_info = inner_info;
        new_ctx.value = map_object;
        new_ctx.desc = desc;

        (void)del_bpf_map(&new_ctx);
        free(map_object);
        break;
    default:
        break;
    }

    bpf_map_delete_elem(inner_fd, &key);
    return 0;
}

static int repeat_field_del(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    unsigned int i;
    int inner_fd, key = 0;
    void *map_object = NULL;
    void *n;
    unsigned int *outer_key;
    struct bpf_map_info *inner_info;

    outer_key = (unsigned int *)((char *)ctx->value + field->offset);
    if (!valid_outer_key(ctx, *outer_key))
        return -EINVAL;

    ret = outer_key_to_inner_map_index(*outer_key, &inner_fd, &inner_info, &key);
    if (ret)
        return ret;

    ret = free_outter_map_entry(ctx, outer_key);
    if (ret)
        return ret;

    n = ((char *)ctx->value) + field->quantifier_offset;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        // lint -fallthrough
    case PROTOBUF_C_TYPE_STRING:
        map_object = calloc(1, inner_info->value_size);
        if (!map_object) {
            ret = -ENOMEM;
            goto end;
        }

        ret = bpf_map_lookup_elem(inner_fd, &key, map_object);
        if (ret < 0)
            goto end;

        for (i = 0; i < *(size_t *)n; i++) {
            outer_key = (unsigned int *)map_object + i;
            indirect_field_del(ctx, *outer_key, field);
        }
    default:
        break;
    }

end:
    bpf_map_delete_elem(inner_fd, &key);
    if (map_object != NULL)
        free(map_object);
    return ret;
}

static int msg_field_del(
    struct op_context *ctx,
    int inner_fd,
    struct bpf_map_info *inner_info,
    int inner_idx,
    const ProtobufCFieldDescriptor *field)
{
    int ret;
    char *map_object = NULL;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    desc = (ProtobufCMessageDescriptor *)field->descriptor;
    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return -EINVAL;

    map_object = malloc(inner_info->value_size);
    if (!map_object)
        return -ENOMEM;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&inner_idx;
    new_ctx.curr_info = inner_info;
    new_ctx.value = map_object;
    new_ctx.desc = desc;

    ret = del_bpf_map(&new_ctx);
    free(map_object);
    return ret;
}

static int field_del(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int inner_fd, inner_idx;
    unsigned int *outer_key;
    struct bpf_map_info *inner_info;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, ctx->value);
        if (ret < 0)
            return ret;

        outer_key = (unsigned int *)((char *)ctx->value + field->offset);
        if (!valid_outer_key(ctx, *outer_key))
            return -EINVAL;

        ret = outer_key_to_inner_map_index(*outer_key, &inner_fd, &inner_info, &inner_idx);
        if (ret)
            return ret;

        free_outter_map_entry(ctx, outer_key);

        if (field->type == PROTOBUF_C_TYPE_STRING) {
            bpf_map_delete_elem(inner_fd, &inner_idx);
            break;
        }

        msg_field_del(ctx, inner_fd, inner_info, inner_idx, field);
        break;
    default:
        break;
    }

    return 0;
}

static int del_bpf_map(struct op_context *ctx)
{
    int ret;
    unsigned int i;
    const ProtobufCMessageDescriptor *desc = ctx->desc;

    ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, ctx->value);
    if (ret < 0)
        return ret;

    for (i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *field = desc->fields + i;

        if (!selected_oneof_field(ctx->value, field) || !valid_field_value(ctx->value, field))
            continue;

        switch (field->label) {
        case PROTOBUF_C_LABEL_REPEATED:
            ret = repeat_field_del(ctx, field);
            if (ret)
                goto end;
            break;
        default:
            ret = field_del(ctx, field);
            if (ret)
                goto end;
            break;
        }
    }

end:
    return bpf_map_delete_elem(ctx->curr_fd, ctx->key);
}

int deserial_delete_elem(void *key, const void *msg_desciptor)
{
    int ret;
    const char *map_name = NULL;
    struct op_context context;
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info info = {0};
    int map_fd;
    unsigned int id;

    if (!key || !msg_desciptor)
        return -EINVAL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        map_name = desc->short_name;

    ret = get_map_id(map_name, &id);
    if (ret)
        return ret;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d", id);
        return ret;
    }

    if (!map_name) {
        ret = bpf_map_delete_elem(map_fd, key);
        goto end;
    }

    init_op_context(context, key, NULL, desc, map_fd, &info);
    context.value = calloc(1, context.curr_info->value_size);
    if (!context.value) {
        ret = -errno;
        goto end;
    }

    normalize_key(&context, key, map_name);
    ret = del_bpf_map(&context);

end:
    if (context.key != NULL)
        free(context.key);
    if (context.value != NULL)
        free(context.value);
    if (map_fd > 0)
        close(map_fd);
    return ret;
}

static void repeat_field_free(void *value, const ProtobufCFieldDescriptor *field)
{
    unsigned int i;
    void *n = ((char *)value) + field->quantifier_offset;
    uintptr_t *ptr_array = *(uintptr_t **)((char *)value + field->offset);

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        for (i = 0; i < *(unsigned int *)n; i++) {
            if (field->type == PROTOBUF_C_TYPE_STRING)
                free_elem((void *)ptr_array[i]);
            else
                deserial_free_elem((void *)ptr_array[i]);
        }
        break;
    default:
        free_elem((void *)ptr_array);
        break;
    }

    return;
}

static void field_free(void *value, const ProtobufCFieldDescriptor *field)
{
    uintptr_t *tobe_free = (uintptr_t *)((char *)value + field->offset);

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        deserial_free_elem((void *)(*tobe_free));
        break;
    case PROTOBUF_C_TYPE_STRING:
        free_elem((void *)*tobe_free);
        break;
    default:
        break;
    }

    return;
}

void deserial_free_elem(void *value)
{
    unsigned int i;
    const char *map_name = NULL;
    const ProtobufCMessageDescriptor *desc;

    if (!value || (uintptr_t)value < UINT32_MAX)
        return;

    desc = ((ProtobufCMessage *)value)->descriptor;
    if (desc && desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        map_name = desc->short_name;

    if (!map_name) {
        LOG_ERR("map_name is NULL");
        free_elem(value);
        return;
    }

    for (i = 0; i < desc->n_fields; i++) {
        const ProtobufCFieldDescriptor *field = desc->fields + i;

        if (!selected_oneof_field(value, field) || !valid_field_value(value, field))
            continue;

        switch (field->label) {
        case PROTOBUF_C_LABEL_REPEATED:
            repeat_field_free(value, field);
            break;
        default:
            field_free(value, field);
            break;
        }
    }

    free_elem(value);
    return;
}

int get_map_infos()
{
    int i, ret;
    unsigned int inner_id;
    char *map_names[] = {
        "KmeshMap64",
        "KmeshMap192",
        "KmeshMap296",
        "KmeshMap1600",
    };

    for (i = 0; i < MAP_TYPE_MAX; i++) {
        ret = get_map_id(map_names[i], &inner_id);
        if (ret)
            return -1;

        ret = get_map_fd_info(inner_id, &g_map_mng.inner_fds[i], &g_map_mng.inner_infos[i]);
        if (ret < 0)
            return ret;
    }
    return 0;
}

void deserial_uninit()
{
    int i;
    for (i = 0; i < MAP_TYPE_MAX; i++) {
        close(g_map_mng.inner_fds[i]);
    }
    return;
}

int map_restore(int map_fd, struct bpf_map_info *map_info, unsigned char *bitmap, unsigned int *start_pos)
{
    void *prev_key;
    unsigned int key = 0;

    while (!bpf_map_get_next_key(map_fd, prev_key, &key)) {
        if (MAP_GET_INDEX(key) >= MAP_MAX_ENTRIES) {
            LOG_ERR("bpf_map_get_next_key key:%u invalid.", key);
            return -1;
        }

        SET_BIT(bitmap, key);
        prev_key = &key;
    }

    *start_pos = ((key + 1) % MAP_MAX_ENTRIES) ?: 1;
    return 0;
}

int maps_restore()
{
    // restore from bpf map
    int i, ret = 0;

    for (i = 0; i < MAP_TYPE_MAX; i++) {
        ret = map_restore(
            g_map_mng.inner_fds[i], &g_map_mng.inner_infos[i], g_map_mng.used_bitmap[i], &g_map_mng.start_pos[i]);
        if (ret) {
            LOG_ERR("map_restore %d failed:%d", i, ret);
            break;
        }
    }
    return ret;
}

int deserial_init()
{
    int ret = 0;

    do {
        ret = get_map_infos();
        if (ret)
            break;

        ret = maps_restore();
        if (ret)
            break;
    } while (0);

    if (ret) {
        deserial_uninit();
        return ret;
    }
    return 0;
}