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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/bpf.h>

#include <protobuf-c/protobuf-c.h>

#include "deserialization_to_bpf_map.h"
#include "../../config/kmesh_marcos_def.h"

#define PRINTF(fmt, args...)                                                                                           \
    do {                                                                                                               \
        printf(fmt, ##args);                                                                                           \
        fflush(stdout);                                                                                                \
    } while (0)

#define LOG_ERR(fmt, args...)  PRINTF(fmt, ##args)
#define LOG_WARN(fmt, args...) PRINTF(fmt, ##args)
#define LOG_INFO(fmt, args...) PRINTF(fmt, ##args)

struct op_context {
    void *key;
    void *value;
    int outter_fd;
    int map_fd;
    int curr_fd;
    struct bpf_map_info *outter_info;
    struct bpf_map_info *inner_info;
    struct bpf_map_info *info;
    struct bpf_map_info *curr_info;
    char *inner_map_object;
    const ProtobufCMessageDescriptor *desc;
};

#define init_op_context(context, k, v, desc, o_fd, fd, o_info, i_info, m_info)                                         \
    do {                                                                                                               \
        (context).key = (k);                                                                                           \
        (context).value = (v);                                                                                         \
        (context).desc = (desc);                                                                                       \
        (context).outter_fd = (o_fd);                                                                                  \
        (context).map_fd = (fd);                                                                                       \
        (context).outter_info = (o_info);                                                                              \
        (context).inner_info = (i_info);                                                                               \
        (context).info = (m_info);                                                                                     \
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

struct inner_map_mng {
    int inner_fd;
    int outter_fd;
    struct bpf_map_info inner_info;
    struct bpf_map_info outter_info;
    struct inner_map_stat inner_maps[MAX_OUTTER_MAP_ENTRIES];
    int elastic_slots[ELASTIC_SLOTS_NUM];
    int used_cnt;          // real used count
    int allocated_cnt;     // real allocated count
    int max_allocated_idx; // max allocated index, there may be holes.
    int init;
    sem_t fin_tasks;
    int elastic_task_exit; // elastic scaling thread exit flag
};

struct task_contex {
    int outter_fd;
    int task_id;
    bool scaleup;
};

#define MAP_IN_MAP_MNG_PERSIST_FILE_PATH "/mnt/mim_mng_persist"
#define MAGIC_NUMBER                     0xb809b8c3
struct persist_info {
    unsigned int magic;
    int used_cnt;          // real used count
    int allocated_cnt;     // real allocated count
    int max_allocated_idx; // max allocated index, there may be holes.
    struct inner_map_stat inner_map_stat[0];
};

struct inner_map_mng g_inner_map_mng = {0};

static int update_bpf_map(struct op_context *ctx);
static void *create_struct(struct op_context *ctx, int *err);
static int del_bpf_map(struct op_context *ctx, int is_inner);
static int free_outter_map_entry(struct op_context *ctx, void *outter_key);

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
    uint32_t n = *(uint32_t *)((char *)value + field->quantifier_offset);

    if ((field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) && field->id != n)
        return 0;

    return 1;
}

static inline int valid_field_value(void *value, const ProtobufCFieldDescriptor *field)
{
    uint32_t val = *(uint32_t *)((char *)value + field->offset);

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

static inline int valid_outter_key(struct op_context *ctx, unsigned int outter_key)
{
    if (outter_key < 0 || outter_key >= MAX_OUTTER_MAP_ENTRIES)
        return 0;

    return 1;
}

static void free_elem(void *ptr)
{
    if ((uintptr_t)ptr < MAX_OUTTER_MAP_ENTRIES)
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

static unsigned int get_map_id(const char *name)
{
    char *ptr = NULL;
    char *map_id = getenv(name);
    if (!map_id)
        return 0;
    return (unsigned int)strtol(map_id, &ptr, 10);
}

static int get_map_ids(const char *name, unsigned int *id, unsigned int *outter_id, unsigned int *inner_id)
{
    char *ptr = NULL;
    char *map_id;

    map_id = (name == NULL) ? getenv("MAP_ID") : getenv(name);
    if (!map_id) {
        LOG_ERR("%s is not set\n", ((name == NULL) ? "MAP_ID" : name));
        return -EINVAL;
    }

    errno = 0;

    *id = (unsigned int)strtol(map_id, &ptr, 10);
    if (!ptr[0]) {
        *outter_id = get_map_id("OUTTER_MAP_ID");
        if (*outter_id == 0)
            return -EINVAL;
    }

    if (!ptr[0]) {
        *inner_id = get_map_id("INNER_MAP_ID");
        if (*inner_id == 0) {
            LOG_ERR("INNER_MAP_ID is not set\n");
            return -EINVAL;
        }
    }
    return -errno;
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

static int free_outter_map_entry(struct op_context *ctx, void *outter_key)
{
    int key = *(int *)outter_key;
    if (key <= 0 || key >= MAX_OUTTER_MAP_ENTRIES)
        return -1;

    if (g_inner_map_mng.inner_maps[key].used) {
        g_inner_map_mng.inner_maps[key].used = 0;
        g_inner_map_mng.used_cnt--;
    }
    return 0;
}

static int alloc_outter_map_entry(struct op_context *ctx)
{
    int i;
    if (!g_inner_map_mng.init || g_inner_map_mng.used_cnt >= g_inner_map_mng.allocated_cnt) {
        LOG_ERR(
            "[%d %d %d]alloc_outter_map_entry failed\n",
            g_inner_map_mng.init,
            g_inner_map_mng.used_cnt,
            g_inner_map_mng.allocated_cnt);
        return -1;
    }

    for (i = 1; i <= g_inner_map_mng.max_allocated_idx; i++) {
        if (g_inner_map_mng.inner_maps[i].used == 0 && g_inner_map_mng.inner_maps[i].allocated) {
            g_inner_map_mng.inner_maps[i].used = 1;
            g_inner_map_mng.used_cnt++;
            return i;
        }
    }

    LOG_ERR(
        "alloc_outter_map_entry all inner_maps in used:%d-%d-%d\n",
        g_inner_map_mng.used_cnt,
        g_inner_map_mng.allocated_cnt,
        g_inner_map_mng.max_allocated_idx);
    return -1;
}

static int outter_key_to_inner_fd(struct op_context *ctx, unsigned int key)
{
    if (g_inner_map_mng.inner_maps[key].allocated)
        return g_inner_map_mng.inner_maps[key].map_fd;
    return -1;
}

static int copy_byte_field_to_map(struct op_context *ctx, int o_index, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;

    struct ProtobufCBinaryData *bytes = (struct ProtobufCBinaryData *)((char *)ctx->value + field->offset);
    unsigned char *save_value = bytes->data;
    *(uintptr_t *)&bytes->data = (size_t)o_index;

    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        free_outter_map_entry(ctx, &o_index);
        return ret;
    }

    inner_fd = outter_key_to_inner_fd(ctx, o_index);
    if (inner_fd < 0)
        return inner_fd;

    memcpy_s(ctx->inner_map_object, ctx->inner_info->value_size, save_value, bytes->len);
    ret = bpf_map_update_elem(inner_fd, &key, ctx->inner_map_object, BPF_ANY);
    return ret;
}

static int copy_sfield_to_map(struct op_context *ctx, int o_index, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    char **value = (char **)((char *)ctx->value + field->offset);
    char *save_value = *value;

    *(uintptr_t *)value = (size_t)o_index;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        free_outter_map_entry(ctx, &o_index);
        return ret;
    }

    inner_fd = outter_key_to_inner_fd(ctx, o_index);
    if (inner_fd < 0)
        return inner_fd;

    strcpy_s(ctx->inner_map_object, ctx->inner_info->value_size, save_value);
    ret = bpf_map_update_elem(inner_fd, &key, ctx->inner_map_object, BPF_ANY);
    return ret;
}

static int copy_msg_field_to_map(struct op_context *ctx, int o_index, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int key = 0;
    int inner_fd;
    void **value = (void **)((char *)ctx->value + field->offset);
    void *msg = *value;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    *(uintptr_t *)value = (size_t)o_index;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        free_outter_map_entry(ctx, &o_index);
        return ret;
    }

    inner_fd = outter_key_to_inner_fd(ctx, o_index);
    if (inner_fd < 0)
        return inner_fd;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));

    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&key;
    new_ctx.value = msg;
    new_ctx.curr_info = ctx->inner_info;

    desc = ((ProtobufCMessage *)new_ctx.value)->descriptor;
    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
        return -EINVAL;
    }

    new_ctx.desc = desc;

    ret = update_bpf_map(&new_ctx);
    return ret;
}

static int field_handle(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int key = 0;

    if (field->type == PROTOBUF_C_TYPE_MESSAGE || field->type == PROTOBUF_C_TYPE_STRING || field->type == PROTOBUF_C_TYPE_BYTES) {
        key = alloc_outter_map_entry(ctx);
        if (key < 0)
            return key;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        return copy_msg_field_to_map(ctx, key, field);
    case PROTOBUF_C_TYPE_STRING:
        return copy_sfield_to_map(ctx, key, field);
    case PROTOBUF_C_TYPE_BYTES:
        return copy_byte_field_to_map(ctx, key, field);
    default:
        break;
    }

    return 0;
}

static int copy_indirect_data_to_map(struct op_context *ctx, int outter_key, void *value, ProtobufCType type)
{
    int ret = 0;
    int inner_fd, key = 0;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    inner_fd = outter_key_to_inner_fd(ctx, outter_key);
    if (inner_fd < 0)
        return inner_fd;

    switch (type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.value = value;
        new_ctx.curr_info = ctx->inner_info;

        desc = ((ProtobufCMessage *)value)->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            return -EINVAL;
        }

        new_ctx.desc = desc;
        ret = update_bpf_map(&new_ctx);
        break;
    case PROTOBUF_C_TYPE_STRING:
        strcpy_s(ctx->inner_map_object, ctx->inner_info->value_size, (char *)value);
        ret = bpf_map_update_elem(inner_fd, &key, ctx->inner_map_object, BPF_ANY);
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
    int outter_key, inner_fd, key = 0;
    void *n = ((char *)ctx->value) + field->quantifier_offset;
    void ***value = (void ***)((char *)ctx->value + field->offset);
    void **origin_value = *value;
    char *inner_map_object;

    outter_key = alloc_outter_map_entry(ctx);
    if (outter_key < 0)
        return outter_key;
    *(uintptr_t *)value = (size_t)outter_key;
    ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
    if (ret) {
        free_outter_map_entry(ctx, &outter_key);
        return ret;
    }

    inner_fd = outter_key_to_inner_fd(ctx, outter_key);
    if (inner_fd < 0)
        return inner_fd;

    inner_map_object = calloc(1, ctx->inner_info->value_size);
    if (!inner_map_object) {
        return -ENOMEM;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        for (i = 0; i < *(unsigned int *)n; i++) {
            outter_key = alloc_outter_map_entry(ctx);
            if (outter_key < 0)
                goto end;

            *((uintptr_t *)inner_map_object + i) = (size_t)outter_key;
            ret = copy_indirect_data_to_map(ctx, outter_key, origin_value[i], field->type);
            if (ret)
                goto end;
        }
        break;
    default:
        memcpy_s(
            inner_map_object,
            ctx->inner_info->value_size,
            (void *)origin_value,
            *(size_t *)n * sizeof_elt_in_repeated_array(field->type));
        break;
    }

end:
    ret1 = bpf_map_update_elem(inner_fd, &key, inner_map_object, BPF_ANY);
    if (ret1) {
        ret = ret1;
        if (indirect_data_type(field->type))
            free_keys(ctx, inner_map_object, *(size_t *)n);
    }

    free(inner_map_object);
    return ret;
}

static int update_bpf_map(struct op_context *ctx)
{
    int ret;
    unsigned int i;
    void *temp_val;
    const ProtobufCMessageDescriptor *desc = ctx->desc;

    if (desc->sizeof_message > ctx->curr_info->value_size) {
        LOG_ERR("map entry size is too small\n");
        return -EINVAL;
    }

    temp_val = malloc(ctx->curr_info->value_size);
    if (!temp_val)
        return -ENOMEM;

    memcpy_s(temp_val, ctx->curr_info->value_size, ctx->value, ctx->curr_info->value_size);
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
                "desc.name:%s field[%d - %s] handle failed:%d, errno:%d\n",
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

static int map_info_check(struct bpf_map_info *outter_info, struct bpf_map_info *inner_info)
{
    if (outter_info->type != BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        LOG_ERR("outter map type must be BPF_MAP_TYPE_ARRAY_OF_MAPS\n");
        return -EINVAL;
    }

    if (outter_info->max_entries < 2 || outter_info->max_entries > MAX_OUTTER_MAP_ENTRIES) {
        LOG_ERR("outter map max_entries must be in[2,%d]\n", MAX_OUTTER_MAP_ENTRIES);
        return -EINVAL;
    }
    return 0;
}

int deserial_update_elem(void *key, void *value)
{
    int ret;
    const char *map_name = NULL;
    struct op_context context = {.inner_map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info outter_info = {0}, inner_info = {0}, info = {0};
    int map_fd, outter_fd = 0, inner_fd = 0;
    unsigned int id, outter_id = 0, inner_id = 0;

    if (!key || !value)
        return -EINVAL;

    desc = ((ProtobufCMessage *)value)->descriptor;
    if (desc && desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        map_name = desc->short_name;

    ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
    if (ret)
        return ret;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d, errno:%d\n", id, errno);
        return ret;
    }

    if (!map_name) {
        ret = bpf_map_update_elem(map_fd, key, value, BPF_ANY);
        goto end;
    }

    ret = get_map_fd_info(inner_id, &inner_fd, &inner_info);
    ret |= get_map_fd_info(outter_id, &outter_fd, &outter_info);
    if (ret < 0 || map_info_check(&outter_info, &inner_info))
        goto end;

    deserial_delete_elem(key, desc);

    init_op_context(context, key, value, desc, outter_fd, map_fd, &outter_info, &inner_info, &info);

    context.inner_map_object = calloc(1, context.inner_info->value_size);
    if (context.inner_map_object == NULL) {
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
    if (context.inner_map_object != NULL)
        free(context.inner_map_object);
    if (map_fd > 0)
        close(map_fd);
    if (outter_fd > 0)
        close(outter_fd);
    if (inner_fd > 0)
        close(inner_fd);
    return ret;
}

static int query_string_field(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int key = 0, ret;
    int inner_fd;
    void *string;
    void *outter_key = (void *)((char *)ctx->value + field->offset);

    inner_fd = outter_key_to_inner_fd(ctx, *(int *)outter_key);
    if (inner_fd < 0)
        return inner_fd;

    string = malloc(ctx->inner_info->value_size);
    if (!string) {
        return -ENOMEM;
    }

    (*(uintptr_t *)outter_key) = (uintptr_t)string;

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
    const ProtobufCMessageDescriptor *desc;
    uintptr_t *outter_key = (uintptr_t *)((char *)ctx->value + field->offset);

    inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
    if (inner_fd < 0)
        return inner_fd;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&key;
    new_ctx.curr_info = ctx->inner_info;

    desc = (ProtobufCMessageDescriptor *)field->descriptor;
    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
        return -EINVAL;
    }

    new_ctx.desc = desc;

    message = create_struct(&new_ctx, &ret);
    *outter_key = (uintptr_t)message;
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

static void *create_indirect_struct(
    struct op_context *ctx, unsigned long outter_key, const ProtobufCFieldDescriptor *field, int *err)
{
    int inner_fd, key = 0;
    void *value;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    inner_fd = outter_key_to_inner_fd(ctx, outter_key);
    if (inner_fd < 0) {
        *err = inner_fd;
        return NULL;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.curr_info = ctx->inner_info;

        desc = (ProtobufCMessageDescriptor *)field->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            *err = -EINVAL;
            return NULL;
        }

        new_ctx.desc = desc;
        value = create_struct(&new_ctx, err);
        return value;
    default:
        value = malloc(ctx->inner_info->value_size);
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
    void *n = ((char *)ctx->value) + field->quantifier_offset;
    uintptr_t *outter_key = (uintptr_t *)((char *)ctx->value + field->offset);

    inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
    if (inner_fd < 0)
        return inner_fd;

    array = calloc(1, ctx->inner_info->value_size);
    if (!array) {
        return -ENOMEM;
    }

    *outter_key = (uintptr_t)array;
    ret = bpf_map_lookup_elem(inner_fd, &key, array);
    if (ret < 0) {
        return ret;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        for (i = 0; i < *(unsigned int *)n; i++) {
            outter_key = (uintptr_t *)array + i;
            *outter_key = (uintptr_t)create_indirect_struct(ctx, *outter_key, field, &ret);
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
            LOG_ERR("create_struct failed, err = %d\n", err);
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
        LOG_ERR("map entry size is too small\n");
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
            LOG_INFO("field[%d] query fail\n", i);
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
    struct op_context context = {.inner_map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info outter_info = {0}, inner_info = {0}, info = {0};
    int map_fd, outter_fd = 0, inner_fd = 0;
    unsigned int id, outter_id = 0, inner_id = 0;

    if (msg_desciptor == NULL)
        return NULL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return NULL;

    map_name = desc->short_name;
    ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
    if (ret)
        return NULL;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d\n", id);
        return NULL;
    }

    ret = get_map_fd_info(inner_id, &inner_fd, &inner_info);
    ret |= get_map_fd_info(outter_id, &outter_fd, &outter_info);
    if (ret < 0 || map_info_check(&outter_info, &inner_info))
        goto end;

    init_op_context(context, NULL, NULL, desc, outter_fd, map_fd, &outter_info, &inner_info, &info);

    value_list_head = create_struct_list(&context, &err);
    if (err != 0) {
        LOG_ERR("create_struct_list failed, err = %d", err);
    }

end:
    if (context.key != NULL)
        free(context.key);
    if (map_fd > 0)
        close(map_fd);
    if (outter_fd > 0)
        close(outter_fd);
    if (inner_fd > 0)
        close(inner_fd);
    return value_list_head;
}

void *deserial_lookup_elem(void *key, const void *msg_desciptor)
{
    int ret, err;
    void *value = NULL;
    const char *map_name = NULL;
    struct op_context context = {.inner_map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info outter_info = {0}, inner_info = {0}, info = {0};
    int map_fd, outter_fd = 0, inner_fd = 0;
    unsigned int id, outter_id = 0, inner_id = 0;

    if (msg_desciptor == NULL || key == NULL)
        return NULL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return NULL;

    map_name = desc->short_name;
    ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
    if (ret)
        return NULL;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d\n", id);
        return NULL;
    }

    ret = get_map_fd_info(inner_id, &inner_fd, &inner_info);
    ret |= get_map_fd_info(outter_id, &outter_fd, &outter_info);
    if (ret < 0 || map_info_check(&outter_info, &inner_info))
        goto end;

    init_op_context(context, key, NULL, desc, outter_fd, map_fd, &outter_info, &inner_info, &info);

    normalize_key(&context, key, map_name);
    value = create_struct(&context, &err);
    if (err != 0) {
        LOG_ERR("create_struct failed, err = %d\n", err);
    }

end:
    if (context.key != NULL)
        free(context.key);
    if (map_fd > 0)
        close(map_fd);
    if (outter_fd > 0)
        close(outter_fd);
    if (inner_fd > 0)
        close(inner_fd);
    return value;
}

static int indirect_field_del(struct op_context *ctx, unsigned int outter_key, const ProtobufCFieldDescriptor *field)
{
    char *inner_map_object = NULL;
    int inner_fd, key = 0;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    if (!valid_outter_key(ctx, outter_key))
        return -EINVAL;

    inner_fd = outter_key_to_inner_fd(ctx, (unsigned long)outter_key);
    if (inner_fd < 0)
        return inner_fd;

    free_outter_map_entry(ctx, &outter_key);

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        desc = (ProtobufCMessageDescriptor *)field->descriptor;
        if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
            return -EINVAL;
        }

        inner_map_object = malloc(ctx->inner_info->value_size);
        if (!inner_map_object) {
            return -ENOMEM;
        }

        memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
        new_ctx.curr_fd = inner_fd;
        new_ctx.key = (void *)&key;
        new_ctx.curr_info = ctx->inner_info;
        new_ctx.value = inner_map_object;
        new_ctx.desc = desc;

        (void)del_bpf_map(&new_ctx, 1);
        free(inner_map_object);
        break;

    default:
        break;
    }

    return 0;
}

static int repeat_field_del(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    unsigned int i;
    int inner_fd, key = 0;
    void *inner_map_object = NULL;
    void *n;
    uintptr_t *outter_key;

    ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, ctx->value);
    if (ret < 0) {
        LOG_WARN("failed to find map(%d) elem: %d.", ctx->curr_fd, ret);
        return ret;
    }

    outter_key = (uintptr_t *)((char *)ctx->value + field->offset);
    if (!valid_outter_key(ctx, *outter_key))
        return -EINVAL;

    inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
    if (inner_fd < 0)
        return inner_fd;

    ret = free_outter_map_entry(ctx, outter_key);
    if (ret)
        return ret;

    n = ((char *)ctx->value) + field->quantifier_offset;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        // lint -fallthrough
    case PROTOBUF_C_TYPE_STRING:
        inner_map_object = calloc(1, ctx->inner_info->value_size);
        if (!inner_map_object) {
            ret = -ENOMEM;
            goto end;
        }

        ret = bpf_map_lookup_elem(inner_fd, &key, inner_map_object);
        if (ret < 0)
            goto end;

        for (i = 0; i < *(size_t *)n; i++) {
            outter_key = (uintptr_t *)inner_map_object + i;
            indirect_field_del(ctx, *outter_key, field);
        }
    default:
        break;
    }

end:
    if (inner_map_object != NULL)
        free(inner_map_object);
    return ret;
}

static int msg_field_del(struct op_context *ctx, int inner_fd, const ProtobufCFieldDescriptor *field)
{
    int key = 0;
    int ret;
    char *inner_map_object = NULL;
    struct op_context new_ctx;
    const ProtobufCMessageDescriptor *desc;

    desc = (ProtobufCMessageDescriptor *)field->descriptor;
    if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        return -EINVAL;

    inner_map_object = malloc(ctx->inner_info->value_size);
    if (!inner_map_object)
        return -ENOMEM;

    memcpy_s(&new_ctx, sizeof(new_ctx), ctx, sizeof(*ctx));
    new_ctx.curr_fd = inner_fd;
    new_ctx.key = (void *)&key;
    new_ctx.curr_info = ctx->inner_info;
    new_ctx.value = inner_map_object;
    new_ctx.desc = desc;

    ret = del_bpf_map(&new_ctx, 1);
    free(inner_map_object);
    return ret;
}

static int field_del(struct op_context *ctx, const ProtobufCFieldDescriptor *field)
{
    int ret;
    int inner_fd;
    uintptr_t *outter_key;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, ctx->value);
        if (ret < 0)
            return ret;

        outter_key = (uintptr_t *)((char *)ctx->value + field->offset);
        if (!valid_outter_key(ctx, *outter_key))
            return -EINVAL;

        inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
        if (inner_fd < 0)
            return inner_fd;

        free_outter_map_entry(ctx, outter_key);

        if (field->type == PROTOBUF_C_TYPE_STRING) {
            break;
        }

        msg_field_del(ctx, inner_fd, field);
        break;
    default:
        break;
    }

    return 0;
}

static int del_bpf_map(struct op_context *ctx, int is_inner)
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
    return (is_inner == 1) ?: bpf_map_delete_elem(ctx->curr_fd, ctx->key);
}

int deserial_delete_elem(void *key, const void *msg_desciptor)
{
    int ret;
    const char *map_name = NULL;
    struct op_context context = {.inner_map_object = NULL};
    const ProtobufCMessageDescriptor *desc;
    struct bpf_map_info outter_info = {0}, inner_info = {0}, info = {0};
    int map_fd, outter_fd = 0, inner_fd = 0;
    unsigned int id, outter_id = 0, inner_id = 0;
    char *inner_map_object = NULL;

    if (!key || !msg_desciptor)
        return -EINVAL;

    desc = (ProtobufCMessageDescriptor *)msg_desciptor;
    if (desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
        map_name = desc->short_name;

    ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
    if (ret)
        return ret;

    ret = get_map_fd_info(id, &map_fd, &info);
    if (ret < 0) {
        LOG_ERR("invalid MAP_ID: %d\n", id);
        return ret;
    }

    if (!map_name) {
        ret = bpf_map_delete_elem(map_fd, key);
        goto end;
    }

    ret = get_map_fd_info(inner_id, &inner_fd, &inner_info);
    ret |= get_map_fd_info(outter_id, &outter_fd, &outter_info);
    if (ret < 0 || map_info_check(&outter_info, &inner_info))
        goto end;

    init_op_context(context, key, NULL, desc, outter_fd, map_fd, &outter_info, &inner_info, &info);

    context.inner_map_object = calloc(1, context.inner_info->value_size);
    context.value = calloc(1, context.curr_info->value_size);
    if (!context.inner_map_object || !context.value) {
        ret = -errno;
        goto end;
    }

    inner_map_object = context.inner_map_object;

    normalize_key(&context, key, map_name);
    ret = del_bpf_map(&context, 0);

end:
    if (context.key != NULL)
        free(context.key);
    if (context.value != NULL)
        free(context.value);
    if (inner_map_object != NULL)
        free(inner_map_object);
    if (map_fd > 0)
        close(map_fd);
    if (outter_fd > 0)
        close(outter_fd);
    if (inner_fd > 0)
        close(inner_fd);
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

    if (!value || (uintptr_t)value < MAX_OUTTER_MAP_ENTRIES)
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

int get_outer_inner_map_infos(
    int *inner_fd, struct bpf_map_info *inner_info, int *outter_fd, struct bpf_map_info *outter_info)
{
    int ret;
    unsigned int outter_id, inner_id;

    outter_id = get_map_id("OUTTER_MAP_ID");
    inner_id = get_map_id("INNER_MAP_ID");
    if (!outter_id || !inner_id)
        return -1;

    ret = get_map_fd_info(inner_id, inner_fd, inner_info);
    ret |= get_map_fd_info(outter_id, outter_fd, outter_info);
    if (ret < 0 || map_info_check(outter_info, inner_info))
        return -1;
    return 0;
}

void outter_map_insert(struct task_contex *ctx)
{
    int i, end, idx, ret = 0;
    pthread_t tid = pthread_self();

    i = (ctx->task_id * TASK_SIZE) ? (ctx->task_id * TASK_SIZE) : 1;
    end = ((i + TASK_SIZE) < MAX_OUTTER_MAP_ENTRIES) ? (i + TASK_SIZE) : MAX_OUTTER_MAP_ENTRIES;
    for (; i < end; i++) {
        idx = g_inner_map_mng.elastic_slots[i];
        if (!g_inner_map_mng.inner_maps[idx].map_fd) {
            continue;
        }

        ret = bpf_map_update_elem(ctx->outter_fd, &idx, &g_inner_map_mng.inner_maps[idx].map_fd, BPF_ANY);
        if (ret)
            break;
        g_inner_map_mng.inner_maps[idx].allocated = 1;
    }

    if (ret)
        LOG_ERR("[%lu]outter_map_insert %d-%d failed:%d\n", tid, i, idx, ret);
    return;
}

void outter_map_delete(struct task_contex *ctx)
{
    int i, end, idx, ret = 0;
    pthread_t tid = pthread_self();

    i = ctx->task_id * TASK_SIZE;
    end = (i + TASK_SIZE);
    for (; i < end; i++) {
        idx = g_inner_map_mng.elastic_slots[i];
        if (g_inner_map_mng.inner_maps[idx].map_fd) {
            continue;
        }

        ret = bpf_map_delete_elem(ctx->outter_fd, &idx);
        if (ret)
            break;
        g_inner_map_mng.inner_maps[idx].allocated = 0;
    }

    if (ret)
        LOG_ERR("[%lu]outter_map_delete %d-%d failed:%d, err:%d\n", tid, i, idx, ret, errno);
    return;
}

void *outter_map_update_task(void *arg)
{
    struct task_contex *ctx = (struct task_contex *)arg;
    if (!ctx)
        return NULL;

    if (ctx->scaleup)
        outter_map_insert(ctx);
    else
        outter_map_delete(ctx);
    free(ctx);
    sem_post(&g_inner_map_mng.fin_tasks);
    return NULL;
}

void wait_sem_value(sem_t *sem, int wait_value)
{
    int sem_val;
    do {
        sem_getvalue(sem, &sem_val);
    } while (sem_val < wait_value);
}

void reset_sem_value(sem_t *sem)
{
    int val;
    while (sem_getvalue(sem, &val) == 0 && val > 0) {
        if (sem_trywait(sem) != 0) {
            break;
        }
    }
    return;
}

int outter_map_update(int outter_fd, bool scaleup)
{
    int i, ret = 0;
    pthread_t tid;
    struct task_contex *task_ctx = NULL;
    int threads = OUTTER_MAP_SCALEIN_STEP / TASK_SIZE;
    if (scaleup)
        threads = OUTTER_MAP_SCALEUP_STEP / TASK_SIZE;

    reset_sem_value(&g_inner_map_mng.fin_tasks);
    for (i = 0; i < threads; i++) {
        task_ctx = (struct task_contex *)malloc(sizeof(struct task_contex));
        if (!task_ctx)
            break;

        task_ctx->task_id = i;
        task_ctx->scaleup = scaleup;
        task_ctx->outter_fd = outter_fd;
        ret = pthread_create(&tid, NULL, outter_map_update_task, task_ctx);
        if (ret) {
            free(task_ctx);
            break;
        }
    }

    if (ret) {
        LOG_ERR("outter_map_update failed:%d\n", ret);
        return ret;
    }

    wait_sem_value(&g_inner_map_mng.fin_tasks, threads);
    return ret;
}

int inner_map_create(struct bpf_map_info *inner_info)
{
    int fd;
#if LIBBPF_HIGHER_0_6_0_VERSION
    LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = inner_info->map_flags);

    fd = bpf_map_create(
        inner_info->type, NULL, inner_info->key_size, inner_info->value_size, inner_info->max_entries, &opts);
#else
    fd = bpf_create_map_name(
        inner_info->type,
        NULL,
        inner_info->key_size,
        inner_info->value_size,
        inner_info->max_entries,
        inner_info->map_flags);
#endif
    return fd;
}

void collect_outter_map_scaleup_slots()
{
    int i = 0, j = 0;
    memset(g_inner_map_mng.elastic_slots, 0, sizeof(int) * ELASTIC_SLOTS_NUM);
    for (; i < MAX_OUTTER_MAP_ENTRIES; i++) {
        if (g_inner_map_mng.inner_maps[i].allocated == 0) {
            g_inner_map_mng.elastic_slots[j++] = i;
            if (j >= OUTTER_MAP_SCALEUP_STEP)
                break;
        }
    }
    LOG_WARN("collect_outter_map_scaleup_slots:%d-%d-%d\n", i, j, g_inner_map_mng.elastic_slots[j - 1]);
    return;
}

void collect_outter_map_scalein_slots()
{
    int i, j = 0;
    memset(g_inner_map_mng.elastic_slots, 0, sizeof(int) * ELASTIC_SLOTS_NUM);
    for (i = g_inner_map_mng.max_allocated_idx; i >= 0; i--) {
        if (g_inner_map_mng.inner_maps[i].used == 0 && g_inner_map_mng.inner_maps[i].allocated == 1) {
            g_inner_map_mng.elastic_slots[j++] = i;
            if (j >= OUTTER_MAP_SCALEIN_STEP)
                break;
        }
    }
    LOG_WARN("collect_outter_map_scalein_slots:%d-%d-%d\n", i, j, g_inner_map_mng.elastic_slots[j - 1]);
    return;
}

int inner_map_batch_create(struct bpf_map_info *inner_info)
{
    int i, fd;

    collect_outter_map_scaleup_slots();
    for (i = 1; i < OUTTER_MAP_SCALEUP_STEP; i++) {
        fd = inner_map_create(inner_info);
        if (fd < 0)
            break;

        g_inner_map_mng.inner_maps[g_inner_map_mng.elastic_slots[i]].map_fd = fd;
    }

    if (i < OUTTER_MAP_SCALEUP_STEP)
        LOG_WARN("[warning]inner_map_create (%d->%d) failed:%d, errno:%d\n", i, MAX_OUTTER_MAP_ENTRIES, fd, errno);
    return 0;
}

void inner_map_batch_delete()
{
    int i, idx;

    collect_outter_map_scalein_slots();
    for (i = 0; i < OUTTER_MAP_SCALEIN_STEP; i++) {
        idx = g_inner_map_mng.elastic_slots[i];
        if (g_inner_map_mng.inner_maps[idx].used == 0 && g_inner_map_mng.inner_maps[idx].map_fd) {
            close(g_inner_map_mng.inner_maps[idx].map_fd);
            g_inner_map_mng.inner_maps[idx].map_fd = 0;
        }
    }
    return;
}

void deserial_uninit(bool persist)
{
    if (persist)
        inner_map_mng_persist();
    else
        remove(MAP_IN_MAP_MNG_PERSIST_FILE_PATH);

    for (int i = 1; i <= g_inner_map_mng.max_allocated_idx; i++) {
        g_inner_map_mng.inner_maps[i].allocated = 0;
        g_inner_map_mng.inner_maps[i].used = 0;
        if (g_inner_map_mng.inner_maps[i].map_fd)
            close(g_inner_map_mng.inner_maps[i].map_fd);
    }

    (void)sem_destroy(&g_inner_map_mng.fin_tasks);
    g_inner_map_mng.elastic_task_exit = 1;
    g_inner_map_mng.used_cnt = 0;
    g_inner_map_mng.allocated_cnt = 0;
    g_inner_map_mng.max_allocated_idx = 0;
    g_inner_map_mng.init = 0;

    close(g_inner_map_mng.inner_fd);
    close(g_inner_map_mng.outter_fd);
    return;
}

int inner_map_scaleup()
{
    int ret;
    float percent = 1;

    if (g_inner_map_mng.allocated_cnt)
        percent = ((float)g_inner_map_mng.used_cnt) / ((float)g_inner_map_mng.allocated_cnt);
    if (percent < OUTTER_MAP_USAGE_HIGH_PERCENT)
        return 0;

    LOG_WARN(
        "Remaining resources are insufficient(%d/%d), and capacity expansion is required.\n",
        g_inner_map_mng.used_cnt,
        g_inner_map_mng.allocated_cnt);

    do {
        ret = inner_map_batch_create(&g_inner_map_mng.inner_info);
        if (ret)
            break;

        ret = outter_map_update(g_inner_map_mng.outter_fd, true);
        if (ret)
            break;

        g_inner_map_mng.allocated_cnt += OUTTER_MAP_SCALEUP_STEP;
        if (g_inner_map_mng.elastic_slots[OUTTER_MAP_SCALEUP_STEP - 1] > g_inner_map_mng.max_allocated_idx)
            g_inner_map_mng.max_allocated_idx = g_inner_map_mng.elastic_slots[OUTTER_MAP_SCALEUP_STEP - 1];
    } while (0);

    if (ret) {
        LOG_ERR("inner_map_scaleup failed:%d\n", ret);
    }
    return ret;
}

int inner_map_scalein()
{
    int i, ret;
    float percent = 1;

    if (g_inner_map_mng.allocated_cnt > OUTTER_MAP_SCALEUP_STEP)
        percent = ((float)g_inner_map_mng.used_cnt) / ((float)g_inner_map_mng.allocated_cnt);
    if (percent > OUTTER_MAP_USAGE_LOW_PERCENT)
        return 0;

    LOG_WARN(
        "The remaining resources are sufficient(%d/%d) and scale-in is required.\n",
        g_inner_map_mng.used_cnt,
        g_inner_map_mng.allocated_cnt);

    inner_map_batch_delete();
    ret = outter_map_update(g_inner_map_mng.outter_fd, false);
    if (ret) {
        LOG_ERR("inner_map_scalein failed:%d\n", ret);
        return ret;
    }

    g_inner_map_mng.allocated_cnt -= OUTTER_MAP_SCALEIN_STEP;
    for (i = g_inner_map_mng.max_allocated_idx; i >= 0; i--) {
        if (g_inner_map_mng.inner_maps[i].allocated) {
            g_inner_map_mng.max_allocated_idx = i;
            break;
        }
    }
    return ret;
}

void *inner_map_elastic_scaling_task(void *arg)
{
    for (;;) {
        if (g_inner_map_mng.elastic_task_exit) {
            LOG_WARN("Receive exit signal for inner-map elastic scaling task.\n");
            break;
        }

        inner_map_scaleup();
        inner_map_scalein();
        usleep(1000);
    }
    return NULL;
}

int inner_map_elastic_scaling()
{
    pthread_t tid;
    return pthread_create(&tid, NULL, inner_map_elastic_scaling_task, NULL);
}

int inner_map_mng_persist()
{
    int i, size;
    FILE *f = NULL;
    struct persist_info *p = NULL;

    if (g_inner_map_mng.init == 0)
        return 0;

    size = sizeof(struct persist_info) + sizeof(struct inner_map_stat) * (g_inner_map_mng.max_allocated_idx + 1);
    p = (struct persist_info *)malloc(size);
    if (!p) {
        LOG_ERR("inner_map_mng_persist malloc failed.\n");
        return -1;
    }

    p->magic = MAGIC_NUMBER;
    p->allocated_cnt = g_inner_map_mng.allocated_cnt;
    p->used_cnt = g_inner_map_mng.used_cnt;
    p->max_allocated_idx = g_inner_map_mng.max_allocated_idx;
    for (i = 0; i <= g_inner_map_mng.max_allocated_idx; i++) {
        p->inner_map_stat[i].map_fd = g_inner_map_mng.inner_maps[i].map_fd;
        p->inner_map_stat[i].used = g_inner_map_mng.inner_maps[i].used;
        p->inner_map_stat[i].allocated = g_inner_map_mng.inner_maps[i].allocated;
    }

    f = fopen(MAP_IN_MAP_MNG_PERSIST_FILE_PATH, "wb");
    if (f == NULL) {
        LOG_ERR("inner_map_mng_persist fopen failed:%d.\n", errno);
        free(p);
        return -1;
    }

    (void)fwrite(p, sizeof(unsigned char), size, f);
    fclose(f);
    LOG_INFO("inner_map_mng_persist succeed.\n");
    return 0;
}

void inner_map_mng_restore_by_persist_stat(struct persist_info *p, struct inner_map_stat *stat)
{
    memcpy(g_inner_map_mng.inner_maps, stat, sizeof(struct inner_map_stat) * (p->max_allocated_idx + 1));

    g_inner_map_mng.used_cnt = p->used_cnt;
    g_inner_map_mng.allocated_cnt = p->allocated_cnt;
    g_inner_map_mng.max_allocated_idx = p->max_allocated_idx;
    return;
}

int inner_map_restore(bool restore)
{
    int size;
    int read_size;
    FILE *f = NULL;
    struct persist_info p;
    struct inner_map_stat *stat = NULL;

    if (!restore) {
        remove(MAP_IN_MAP_MNG_PERSIST_FILE_PATH);
        return 0;
    }

    f = fopen(MAP_IN_MAP_MNG_PERSIST_FILE_PATH, "rb");
    if (f == NULL)
        return 0;

    read_size = (int)fread(&p, sizeof(unsigned char), sizeof(struct persist_info), f);
    if (read_size != sizeof(struct persist_info) || p.magic != MAGIC_NUMBER) {
        LOG_WARN("inner_map_restore invalid size:%d/%lu\n", read_size, sizeof(struct persist_info));
        fclose(f);
        return 0;
    }

    size = sizeof(struct inner_map_stat) * (p.max_allocated_idx + 1);
    stat = (struct inner_map_stat *)malloc(size);
    if (!stat) {
        LOG_ERR("inner_map_restore alloc failed.\n");
        fclose(f);
        return -1;
    }

    read_size = (int)fread(stat, sizeof(unsigned char), size, f);
    if (read_size != size) {
        LOG_WARN("inner_map_restore persist_stat invalid size:%d/%d\n", read_size, size);
        fclose(f);
        free(stat);
        return 0;
    }

    inner_map_mng_restore_by_persist_stat(&p, stat);
    free(stat);
    fclose(f);
    return 0;
}

int deserial_init(bool restore)
{
    int ret = 0;

    do {
        sem_init(&g_inner_map_mng.fin_tasks, 0, 0);
        ret = get_outer_inner_map_infos(
            &g_inner_map_mng.inner_fd,
            &g_inner_map_mng.inner_info,
            &g_inner_map_mng.outter_fd,
            &g_inner_map_mng.outter_info);
        if (ret)
            break;

        ret = inner_map_restore(restore);
        if (ret)
            break;

        ret = inner_map_scaleup();
        if (ret)
            break;

        ret = inner_map_elastic_scaling();
        if (ret)
            break;
    } while (0);

    if (ret) {
        deserial_uninit(false);
        return ret;
    }
    g_inner_map_mng.init = 1;
    return 0;
}
