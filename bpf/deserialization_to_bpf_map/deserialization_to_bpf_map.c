#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <protobuf-c.h>

#include "deserialization_to_bpf_map.h"

#define LOG_ERR(fmt, args...)	printf(fmt, ## args)
#define LOG_INFO(fmt, args...)	printf(fmt, ## args)

#define FREE_MAP_SIZE	(MAX_OUTTER_MAP_ENTRIES / (sizeof(uint32_t) * 8))

struct outter_map_alloc_control {
	int used;
	uint32_t free_map[FREE_MAP_SIZE];
};

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

#define init_op_context(context, key, val, desc, o_fd, fd, o_info,	\
			i_info, m_info)	\
do {					\
	context.key = key;		\
	context.value = val;		\
	context.desc = desc;		\
	context.outter_fd = o_fd;	\
	context.map_fd = fd;		\
	context.outter_info = o_info;	\
	context.inner_info = i_info;	\
	context.info = m_info;		\
	context.curr_info = m_info;	\
	context.curr_fd = fd;		\
} while(0)

static int update_bpf_map(struct op_context *context);
static void* create_struct(struct op_context *ctx, int *err);
static int del_bpf_map(struct op_context *ctx, int is_inner);
static int free_outter_map_entry(struct op_context *ctx, void *outter_key);

static inline size_t
sizeof_elt_in_repeated_array(ProtobufCType type)
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
	}

	return 0;
}

static inline int valid_outter_key(struct op_context *ctx, int outter_key)
{
	if (outter_key >= ctx->outter_info->max_entries || !outter_key)
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
	int i, key;

	for (i = 0; i < n; i++) {
		key = *((uintptr_t*)keys + i);
		if (!key)
			return;

		free_outter_map_entry(ctx, &key);
	}
}

static int get_map_ids(const char *name, int *id, int *outter_id, int *inner_id)
{
	char *ptr = NULL;
	char *map_id, *map_in_map_id;

	map_id = (name == NULL) ? getenv("MAP_ID") : getenv(name);
	if (!map_id) {
		LOG_ERR("%s is not set\n", (name == NULL) ? "MAP_ID" : name);
		return -EINVAL;
	}

	errno = 0;

	*id = strtol(map_id, &ptr, 10);
	if (!ptr[0]) {
		map_in_map_id = getenv("OUTTER_MAP_ID");
		if (!map_in_map_id)
			return 0;
		*outter_id = strtol(map_in_map_id, &ptr, 10);
	}

	if (!ptr[0]) {
		map_in_map_id = getenv("INNER_MAP_ID");
		if (!map_in_map_id) {
			LOG_ERR("INNER_MAP_ID is not set\n");
			return -EINVAL;
		}
		*inner_id = strtol(map_in_map_id, &ptr, 10);
	}
	return -errno;
}

static int get_map_fd_info(int id, int *map_fd, struct bpf_map_info *info)
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

static int alloc_and_set_inner_map(struct op_context *ctx, int key)
{
	int fd, ret;
	struct bpf_map_info *inner_info = ctx->inner_info;

	fd = bpf_create_map_name(inner_info->type, NULL, inner_info->key_size,
			    inner_info->value_size, inner_info->max_entries,
			    inner_info->map_flags);
	if (fd < 0)
		return fd;

	ret = bpf_map_update_elem(ctx->outter_fd, &key, &fd, BPF_ANY);
	close(fd);

	return ret;
}

static int find_free_outter_map_entry(struct op_context *ctx,
					struct outter_map_alloc_control *a_ctl)
{
	int i, index;

	for (i = 0; i < FREE_MAP_SIZE; i++) {
		if (a_ctl->free_map[i]) {
			index = __builtin_ffs(a_ctl->free_map[i]);
			a_ctl->free_map[i] &= ~(1U << (index - 1));
			return (index - 1 + i * 32);
		}
	}

	return -ENOENT;
}

static int free_outter_map_entry(struct op_context *ctx, void *outter_key)
{
	int ret;
	int key = 0, i = *(int*)outter_key;
	int inner_map_fd;
	__u32 inner_map_id;
	struct outter_map_alloc_control *a_ctl;

	ret = bpf_map_delete_elem(ctx->outter_fd, outter_key);
	if (ret)
		return ret;

	ret = bpf_map_lookup_elem(ctx->outter_fd, &key, &inner_map_id);
	if (ret < 0)
		return 0;

	inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
	if (inner_map_fd < 0)
		return inner_map_fd;

	ret = bpf_map_lookup_elem(inner_map_fd, &key, ctx->inner_map_object);
	if (ret < 0)
		return ret;

	a_ctl = (struct outter_map_alloc_control *)ctx->inner_map_object;
	a_ctl->used--;
	a_ctl->free_map[i/32] |= (1U << (i % 32));
	bpf_map_update_elem(inner_map_fd, &key, a_ctl, BPF_ANY);

	return 0;
}

static int alloc_outter_map_entry(struct op_context *ctx)
{
	int ret;
	int first = 0;
	int key = 0, ret_key;
	int inner_map_fd;
	__u32 inner_map_id;
	struct outter_map_alloc_control *a_ctl;

retry:
	ret = bpf_map_lookup_elem(ctx->outter_fd, &key, &inner_map_id);
	if (ret < 0) {
		if (-errno != -ENOENT)
			return ret;
		ret = alloc_and_set_inner_map(ctx, key);
		if (ret)
			return ret;

		first = 1;
		goto retry;
	}

	inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
	if (inner_map_fd < 0)
		return inner_map_fd;

	ret = bpf_map_lookup_elem(inner_map_fd, &key, ctx->inner_map_object);
	if (ret < 0) {
		close(inner_map_fd);
		return ret;
	}

	a_ctl = (struct outter_map_alloc_control *)ctx->inner_map_object;
	if (a_ctl->used >= ctx->outter_info->max_entries) {
		LOG_ERR("outter map entries has consumed out\n");
		close(inner_map_fd);
		return -ENOENT;
	}

	if (first) {
		memset(a_ctl->free_map, 0xff, sizeof(a_ctl->free_map));
		a_ctl->free_map[0] &= ~(1U << 0);
	}

	ret_key = find_free_outter_map_entry(ctx, a_ctl);
	if (ret_key > 0) {
		ret = alloc_and_set_inner_map(ctx, ret_key);
		if (ret) {
			close(inner_map_fd);
			return ret;
		}

		a_ctl->used += first + 1;
		bpf_map_update_elem(inner_map_fd, &key, a_ctl, BPF_ANY);
	}

	close(inner_map_fd);
	return ret_key;
}

static int outter_key_to_inner_fd(struct op_context *ctx, int key)
{
	int ret;
	__u32 inner_map_id;

	ret = bpf_map_lookup_elem(ctx->outter_fd, &key, &inner_map_id);
	if (ret < 0)
		return ret;

	return bpf_map_get_fd_by_id(inner_map_id);
}

static int copy_sfield_to_map(struct op_context *ctx, int o_index,
			    const ProtobufCFieldDescriptor *field)
{
	int ret;
	int key = 0;
	int inner_fd;
	char **value = (char**)((char*)ctx->value + field->offset);
	char *save_value = *value;

	*(uintptr_t *)value = o_index;
	ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
	if (ret) {
		free_outter_map_entry(ctx, &o_index);
		return ret;
	}

	inner_fd = outter_key_to_inner_fd(ctx, o_index);
	if (inner_fd < 0)
		return inner_fd;

#if 0
	ret = bpf_map_lookup_elem(inner_fd, &key, ctx->inner_map_object);
	if (ret < 0) {
		close(inner_fd);
		return ret;
	}
#endif

	strcpy(ctx->inner_map_object, save_value);
	ret = bpf_map_update_elem(inner_fd, &key, ctx->inner_map_object, BPF_ANY);
	close(inner_fd);
	return ret;
}

static int copy_msg_field_to_map(struct op_context *ctx, int o_index,
			const ProtobufCFieldDescriptor *field)
{
	int ret;
	int key = 0;
	int inner_fd;
	void **value = (void**)((char*)ctx->value + field->offset);
	void *msg = *value;
	struct op_context new_ctx;
	const ProtobufCMessageDescriptor *desc;

	*(uintptr_t*)value = o_index;
	ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
	if (ret) {
		free_outter_map_entry(ctx, &o_index);
		return ret;
	}

	inner_fd = outter_key_to_inner_fd(ctx, o_index);
	if (inner_fd < 0)
		return inner_fd;

	memcpy(&new_ctx, ctx, sizeof(*ctx));

	new_ctx.curr_fd = inner_fd;
	new_ctx.key = (void*)&key;
	new_ctx.value = msg;
	new_ctx.curr_info = ctx->inner_info;

	desc = ((ProtobufCMessage *)new_ctx.value)->descriptor;
	if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
		close(inner_fd);
		return -EINVAL;
	}

	new_ctx.desc = desc;

	ret = update_bpf_map(&new_ctx);
	close(inner_fd);
	return ret;
}

static int field_handle(struct op_context *ctx,
			    const ProtobufCFieldDescriptor *field)
{
	int key = 0;

	if (field->type == PROTOBUF_C_TYPE_MESSAGE ||
		field->type == PROTOBUF_C_TYPE_STRING) {
		key = alloc_outter_map_entry(ctx);
		if (key < 0)
			return key;
	}

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
		return copy_msg_field_to_map(ctx, key, field);
	case PROTOBUF_C_TYPE_STRING:
		return copy_sfield_to_map(ctx, key, field);
	default:
		break;
	}

	return 0;
}

static int copy_indirect_data_to_map(struct op_context *ctx, int outter_key,
					    void *value, ProtobufCType type)
{
	int ret, inner_fd, key = 0;
	struct op_context new_ctx;
	const ProtobufCMessageDescriptor *desc;

	inner_fd = outter_key_to_inner_fd(ctx, outter_key);
	if (inner_fd < 0)
		return inner_fd;

#if 0
	ret = bpf_map_lookup_elem(inner_fd, &key, ctx->inner_map_object);
	if (ret < 0) {
		close(inner_fd);
		return ret;
	}
#endif

	switch (type) {
	case PROTOBUF_C_TYPE_MESSAGE:
		memcpy(&new_ctx, ctx, sizeof(*ctx));
		new_ctx.curr_fd = inner_fd;
		new_ctx.key = (void*)&key;
		new_ctx.value = value;
		new_ctx.curr_info = ctx->inner_info;

		desc = ((ProtobufCMessage *)value)->descriptor;
		if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
			close(inner_fd);
			return -EINVAL;
		}

		new_ctx.desc = desc;
		ret = update_bpf_map(&new_ctx);
		break;
	case PROTOBUF_C_TYPE_STRING:
		strcpy(ctx->inner_map_object, (char*)value);
		ret = bpf_map_update_elem(inner_fd, &key,
					   ctx->inner_map_object, BPF_ANY);
		break;
	default:
		break;
	}

	close(inner_fd);
	return ret;
}

static bool indirect_data_type(ProtobufCType	type)
{
	switch (type) {
	case PROTOBUF_C_TYPE_MESSAGE:
	case PROTOBUF_C_TYPE_STRING:
		return true;
	default:
		return false;
	}
}

static int repeat_field_handle(struct op_context *ctx,
				    const ProtobufCFieldDescriptor *field)
{
	int ret, ret1;
	int i, outter_key, inner_fd, key = 0;
	void *n = ((char*)ctx->value) + field->quantifier_offset;
	void ***value = (void***)((char*)ctx->value + field->offset);
	void **origin_value = *value;
	char *inner_map_object;

	outter_key = alloc_outter_map_entry(ctx);
	if (outter_key < 0)
		return outter_key;

	*(uintptr_t*)value = outter_key;
	ret = bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
	if (ret) {
		free_outter_map_entry(ctx, &outter_key);
		return ret;
	}

	inner_fd = outter_key_to_inner_fd(ctx, outter_key);
	if (inner_fd < 0)
		return inner_fd;

	inner_map_object = malloc(ctx->inner_info->value_size);
	if (!inner_map_object) {
		close(inner_fd);
		return -ENOMEM;
	}

	memset(inner_map_object, 0, ctx->inner_info->value_size);

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
	case PROTOBUF_C_TYPE_STRING:
		for (i = 0; i < *(size_t*)n; i++) {
			outter_key = alloc_outter_map_entry(ctx);
			if (outter_key < 0)
				goto end;

			*((uintptr_t*)inner_map_object + i) = outter_key;
			ret = copy_indirect_data_to_map(ctx, outter_key,
				origin_value[i], field->type);
			if (ret)
				goto end;
		}
		break;
	default:
		memcpy(inner_map_object, (void*)origin_value,
			*(size_t*)n * sizeof_elt_in_repeated_array(field->type));
		break;
	}

end:
	ret1 = bpf_map_update_elem(inner_fd, &key, inner_map_object, BPF_ANY);
	if (ret1) {
		ret = ret1;
		if (indirect_data_type(field->type))
			free_keys(ctx, inner_map_object, *(size_t*)n);
	}

	free(inner_map_object);
	close(inner_fd);

	return ret;

}

static int update_bpf_map(struct op_context *ctx)
{
	int i, ret;
	const ProtobufCMessageDescriptor *desc = ctx->desc;

	if (desc->sizeof_message > ctx->curr_info->value_size) {
		LOG_ERR("map entry size is too small\n");
		return -EINVAL;
	}

	for (i = 0; i < desc->n_fields; i++) {
		const ProtobufCFieldDescriptor *field = desc->fields + i;

		switch (field->label) {
		case PROTOBUF_C_LABEL_REPEATED:
			ret = repeat_field_handle(ctx, field);
			break;
		default:
			ret = field_handle(ctx, field);
			break;
		}

		if (ret) {
			LOG_INFO("field[%d] handle fail\n", i);
			return ret;
		}
	}

	return bpf_map_update_elem(ctx->curr_fd, ctx->key, ctx->value, BPF_ANY);
}

static int map_info_check(struct bpf_map_info *outter_info,
			       struct bpf_map_info *inner_info)
{
	if (outter_info->type != BPF_MAP_TYPE_ARRAY_OF_MAPS) {
		LOG_ERR("outter map type must be BPF_MAP_TYPE_ARRAY_OF_MAPS\n");
		return -EINVAL;
	}

	if (outter_info->max_entries < 2 ||
		outter_info->max_entries > MAX_OUTTER_MAP_ENTRIES) {
		LOG_ERR("outter map max_entries must be in[2,%d]\n",
				MAX_OUTTER_MAP_ENTRIES);
		return -EINVAL;
	}

	if (inner_info->value_size < sizeof(struct outter_map_alloc_control)) {
		LOG_ERR("inner map value_size must be large than %ld(bytes)\n",
			sizeof(struct outter_map_alloc_control));
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
	struct bpf_map_info outter_info, inner_info, info;
	int map_fd, outter_fd = 0, inner_fd = 0;
	int id, outter_id = 0, inner_id = 0;

	if (!key || !value)
		return -EINVAL;

	desc = ((ProtobufCMessage *)value)->descriptor;
	if (desc && desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
		map_name = desc->name;

	ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
	if (ret)
		return ret;

	ret = get_map_fd_info(id, &map_fd, &info);
	if (ret < 0) {
		LOG_ERR("invlid MAP_ID: %d\n", id);
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

	init_op_context(context, key, value, desc, outter_fd, map_fd,
			&outter_info, &inner_info, &info);

	context.inner_map_object = malloc(context.inner_info->value_size);
	if (context.inner_map_object == NULL) {
		ret = -errno;
		goto end;
	}

	memset(context.inner_map_object, 0, context.inner_info->value_size);
	ret = update_bpf_map(&context);
	if (ret)
		deserial_delete_elem(key, desc);

end:
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

static int query_string_field(struct op_context *ctx,
			  	   const ProtobufCFieldDescriptor *field)
{
	int key = 0, ret;
	int inner_fd;
	void *string;
	void *outter_key = (void*)((char*)ctx->value + field->offset);

	inner_fd = outter_key_to_inner_fd(ctx, *(int*)outter_key);
	if (inner_fd < 0)
		return inner_fd;

	string = malloc(ctx->inner_info->value_size);
	if (!string) {
		close(inner_fd);
		return -ENOMEM;
	}

	(*(uintptr_t *)outter_key) = (uintptr_t)string;

	ret = bpf_map_lookup_elem(inner_fd, &key, string);
	close(inner_fd);
	return ret;
}

static int query_message_field(struct op_context *ctx,
			      const ProtobufCFieldDescriptor *field)
{
	int ret;
	int key = 0;
	int inner_fd;
	void *message;
	struct op_context new_ctx;
	const ProtobufCMessageDescriptor *desc;
	uintptr_t *outter_key = (uintptr_t *)((char*)ctx->value + field->offset);

	inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
	if (inner_fd < 0)
		return inner_fd;

	memcpy(&new_ctx, ctx, sizeof(*ctx));
	new_ctx.curr_fd = inner_fd;
	new_ctx.key = (void*)&key;
	new_ctx.curr_info = ctx->inner_info;

	desc = (ProtobufCMessageDescriptor*)field->descriptor;
	if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
		close(inner_fd);
		return -EINVAL;
	}

	new_ctx.desc = desc;
	
	message = create_struct(&new_ctx, &ret);
	*outter_key = (uintptr_t)message;
	close(inner_fd);
	 return ret;
}

static int field_query(struct op_context *ctx,
			  const ProtobufCFieldDescriptor *field)
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

static void* create_indirect_struct(struct op_context *ctx, int outter_key,
					  const ProtobufCFieldDescriptor *field,
					  int *err)
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
		memcpy(&new_ctx, ctx, sizeof(*ctx));
		new_ctx.curr_fd = inner_fd;
		new_ctx.key = (void*)&key;
		new_ctx.curr_info = ctx->inner_info;

		desc = (ProtobufCMessageDescriptor*)field->descriptor;
		if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
			*err = -EINVAL;
			close(inner_fd);
			return NULL;
		}

		new_ctx.desc = desc;
		value = create_struct(&new_ctx, err);
		close(inner_fd);
		return value;
	default:
		value = malloc(ctx->inner_info->value_size);
		if (!value) {
			*err = -ENOMEM;
			close(inner_fd);
			return NULL;
		}

		*err = bpf_map_lookup_elem(inner_fd, &key, value);
		if (*err < 0) {
			close(inner_fd);
			return value;
		}

		break;
	}

	close(inner_fd);
	*err = 0;
	return value;
}
			  	
static int repeat_field_query(struct op_context *ctx,
			     const ProtobufCFieldDescriptor *field)
{
	int i, ret;
	int key = 0;
	int inner_fd;
	void *array;
	void *n = ((char*)ctx->value) + field->quantifier_offset;
	uintptr_t *outter_key = (uintptr_t*)((char*)ctx->value + field->offset);

	inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
	if (inner_fd < 0)
		return inner_fd;

	array = malloc(ctx->inner_info->value_size);
	if (!array) {
		close(inner_fd);
		return -ENOMEM;
	}

	memset(array, 0, ctx->inner_info->value_size);

	*outter_key = (uintptr_t)array;
	ret = bpf_map_lookup_elem(inner_fd, &key, array);
	if (ret < 0) {
		close(inner_fd);
		return ret;
	}

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
	case PROTOBUF_C_TYPE_STRING:
		for (i = 0; i < *(size_t*)n; i++) {
			outter_key = (uintptr_t*)array + i;
			*outter_key = (uintptr_t)create_indirect_struct(ctx,
					*outter_key, field, &ret);
			if (ret)
				break;
		}
		break;
	default:
		break;
	}

	close(inner_fd);
	return ret;
}

static void* create_struct(struct op_context *ctx, int *err)
{
	void *value;
	int i, ret;
	const ProtobufCMessageDescriptor *desc = ctx->desc;

	*err = 0;

	if (desc->sizeof_message > ctx->curr_info->value_size) {
		LOG_ERR("map entry size is too small\n");
		return NULL;
	}

	value = malloc(ctx->curr_info->value_size);
	if (!value)
		return value;

	memset(value, 0, ctx->curr_info->value_size);

	ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, value);
	if (ret < 0) { 
		free(value);
		return NULL;
	}

	ctx->value = value;
	for (i = 0; i < desc->n_fields; i++) {
		const ProtobufCFieldDescriptor *field = desc->fields + i;

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
			return value;
		}
	}

	return value;
}

void* deserial_lookup_elem(void *key, const void *msg_desciptor)
{
	int ret, err;
	void *value = NULL;
	const char *map_name = NULL;
	struct op_context context = {.inner_map_object = NULL};
	const ProtobufCMessageDescriptor *desc;
	struct bpf_map_info outter_info, inner_info, info;
	int map_fd, outter_fd = 0, inner_fd = 0;
	int id, outter_id = 0, inner_id = 0;

	if (msg_desciptor == NULL || key == NULL)
		return NULL;

	desc = (ProtobufCMessageDescriptor*)msg_desciptor;
	if (desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
		return NULL;

	map_name = desc->name;
	ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
	if (ret)
		return NULL;

	ret = get_map_fd_info(id, &map_fd, &info);
	if (ret < 0) {
		LOG_ERR("invlid MAP_ID: %d\n", id);
		return NULL;
	}

	ret = get_map_fd_info(inner_id, &inner_fd, &inner_info);
	ret |= get_map_fd_info(outter_id, &outter_fd, &outter_info);
	if (ret < 0 || map_info_check(&outter_info, &inner_info))
		goto end;

	init_op_context(context, key, NULL, desc, outter_fd, map_fd,
			&outter_info, &inner_info, &info);

	value = create_struct(&context, &err);
	if (err != 0) {
		deserial_free_elem(value);
		value = NULL;
	}

end:
	if (map_fd > 0)
		close(map_fd);
	if (outter_fd > 0)
		close(outter_fd);
	if (inner_fd > 0)
		close(inner_fd);
	return value;
}

static int indirect_field_del(struct op_context *ctx, int outter_key,
				 const ProtobufCFieldDescriptor *field)
{
	int inner_fd, key = 0;
	struct op_context new_ctx;
	const ProtobufCMessageDescriptor *desc;
		
	if (!valid_outter_key(ctx, outter_key))
		return -EINVAL;
	
	inner_fd = outter_key_to_inner_fd(ctx, outter_key);
	if (inner_fd < 0)
		return inner_fd;

	free_outter_map_entry(ctx, &outter_key);

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:	
		desc = (ProtobufCMessageDescriptor*)field->descriptor;
		if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC) {
			close(inner_fd);
			return -EINVAL;
		}

		memcpy(&new_ctx, ctx, sizeof(*ctx));
		new_ctx.curr_fd = inner_fd;
		new_ctx.key = (void*)&key;
		new_ctx.curr_info = ctx->inner_info;
		new_ctx.value = new_ctx.inner_map_object;
		new_ctx.desc = desc;

		return del_bpf_map(&new_ctx, 1);
		
	default:
		break;
	}

	close(inner_fd);
	return 0;
}

static int repeat_field_del(struct op_context *ctx,
				 const ProtobufCFieldDescriptor *field)
{
	int i, ret;
	int inner_fd, key = 0;
	void *inner_map_object = NULL;
	void *n;
	uintptr_t *outter_key;

	ret = bpf_map_lookup_elem(ctx->curr_fd, ctx->key, ctx->value);
	if (ret < 0)
		return ret;

	outter_key = (uintptr_t*)((char*)ctx->value + field->offset);
	if (!valid_outter_key(ctx, *outter_key))
		return -EINVAL;

	inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
	if (inner_fd < 0)
		return inner_fd;

	ret = free_outter_map_entry(ctx, outter_key);
	if (ret)
		return ret;

	n = ((char*)ctx->value) + field->quantifier_offset;

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
	case PROTOBUF_C_TYPE_STRING:
		inner_map_object = malloc(ctx->inner_info->value_size);
		if (!inner_map_object) {
			ret = -ENOMEM;
			goto end;
		}
		memset(inner_map_object, 0, ctx->inner_info->value_size);

		ret = bpf_map_lookup_elem(inner_fd, &key, inner_map_object);
		if (ret < 0)
			goto end;

		for (i = 0; i < *(size_t*)n; i++) {
			outter_key = (uintptr_t*)inner_map_object + i;
			indirect_field_del(ctx, *outter_key, field);
		}
	default:
		break;
	}

end:
	if (inner_map_object != NULL)
		free(inner_map_object);
	close(inner_fd);
	return ret;
}

static int msg_field_del(struct op_context *ctx, int inner_fd,
			     const ProtobufCFieldDescriptor *field)
{
	int key = 0;
	struct op_context new_ctx;
	const ProtobufCMessageDescriptor *desc;

	desc = (ProtobufCMessageDescriptor*)field->descriptor;
	if (!desc || desc->magic != PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
		return -EINVAL;

	memcpy(&new_ctx, ctx, sizeof(*ctx));
	new_ctx.curr_fd = inner_fd;
	new_ctx.key = (void*)&key;
	new_ctx.curr_info = ctx->inner_info;
	new_ctx.value = new_ctx.inner_map_object;
	new_ctx.desc = desc;

	return del_bpf_map(&new_ctx, 1);
}

static int field_del(struct op_context *ctx,
			  const ProtobufCFieldDescriptor *field)
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

		outter_key = (uintptr_t*)((char*)ctx->value + field->offset);
		if (!valid_outter_key(ctx, *outter_key))
			return -EINVAL;

		inner_fd = outter_key_to_inner_fd(ctx, *outter_key);
		if (inner_fd < 0)
			return inner_fd;

		free_outter_map_entry(ctx, outter_key);

		if (field->type == PROTOBUF_C_TYPE_STRING) {
			close(inner_fd);
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
	
	int i, ret;
	const ProtobufCMessageDescriptor *desc = ctx->desc;

	for (i = 0; i < desc->n_fields; i++) {
		const ProtobufCFieldDescriptor *field = desc->fields + i;

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
	return (is_inner == 1) ? close(ctx->curr_fd) :
		bpf_map_delete_elem(ctx->curr_fd, ctx->key);
}

int deserial_delete_elem(void *key, const void *msg_desciptor)
{
	int ret;
	const char *map_name = NULL;
	struct op_context context = {.inner_map_object = NULL};
	const ProtobufCMessageDescriptor *desc;
	struct bpf_map_info outter_info, inner_info, info;
	int map_fd, outter_fd = 0, inner_fd = 0;
	int id, outter_id = 0, inner_id = 0;

	if (!key || !msg_desciptor)
		return -EINVAL;

	desc = (ProtobufCMessageDescriptor *)msg_desciptor;
	if (desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
		map_name = desc->name;

	ret = get_map_ids(map_name, &id, &outter_id, &inner_id);
	if (ret)
		return ret;

	ret = get_map_fd_info(id, &map_fd, &info);
	if (ret < 0) {
		LOG_ERR("invlid MAP_ID: %d\n", id);
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


	init_op_context(context, key, NULL, desc, outter_fd, map_fd,
			&outter_info, &inner_info, &info);

	context.inner_map_object = malloc(context.inner_info->value_size);
	context.value = malloc(context.curr_info->value_size);
	if (!context.inner_map_object || !context.value) {
		ret = -errno;
		goto end;
	}

	memset(context.inner_map_object, 0, context.inner_info->value_size);
	memset(context.value, 0, context.curr_info->value_size);

	ret = del_bpf_map(&context, 0);

end:
	if (context.value != NULL)
		free(context.value);
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


static void repeat_field_free(void *value,
				   const ProtobufCFieldDescriptor *field)
{
	int i;
	void *n = ((char*)value) + field->quantifier_offset;
	uintptr_t *ptr_array = *(uintptr_t**)((char*)value + field->offset);

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
	case PROTOBUF_C_TYPE_STRING:
		for (i = 0; i < *(size_t*)n; i++) {
			if (field->type == PROTOBUF_C_TYPE_STRING)
				free_elem((void*)ptr_array[i]);
			else
				deserial_free_elem((void*)ptr_array[i]);
		}
		break;
	default:
		free_elem((void*)ptr_array);
		break;
	}

	return;
}

static void field_free(void *value,
			  const ProtobufCFieldDescriptor *field)
{
	uintptr_t *tobe_free = (uintptr_t *)((char*)value + field->offset);

	switch (field->type) {
	case PROTOBUF_C_TYPE_MESSAGE:
		deserial_free_elem((void*)(*tobe_free));
		break;
	case PROTOBUF_C_TYPE_STRING:
		free_elem((void*)*tobe_free);
		break;
	default:
		break;
	}

	return;
}

void deserial_free_elem(void *value)
{
	int i;
	const char *map_name = NULL;
	const ProtobufCMessageDescriptor *desc;

	if (!value || (uintptr_t)value < MAX_OUTTER_MAP_ENTRIES)
		return;

	desc = ((ProtobufCMessage *)value)->descriptor;
	if (desc && desc->magic == PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC)
		map_name = desc->name;

	if (!map_name) {
		LOG_ERR("map_name is NULL");
		free_elem(value);
		return;
	}

	for (i = 0; i < desc->n_fields; i++) {
		const ProtobufCFieldDescriptor *field = desc->fields + i;

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
