/*
 * Copyright 2023 The Kmesh Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation
 * Author: liuxin
 * Create: 2022-08-24
 */
#include "kmesh_parse_http_1_1.h"

#define LF          (char)'\n'
#define CR          (char)'\r'
#define FIELD_SPLIT ':'
#define SPACE       ' '

#define METHOD_STRING_LENGTH  7
#define URI_STRING_LENGTH     4
#define VERSION_STRING_LENGTH 8
#define STATUS_STRING_LENGTH  7
#define REASON_STRING_LENGTH  7

enum state {
    ST_START,
    ST_VERSION,
    ST_NEW_LINE,
    // request
    ST_METHOD,
    ST_SPACE_BEFORE_URI,
    ST_URI,
    ST_SPACE_BEFORE_VERSION,
    // respose
    ST_SPACE_BEFORE_STATUS_CODE,
    ST_STATUS_CODE,
    ST_SPACE_BEFORE_REASON,
    ST_REASON,
    // field
    ST_FIELD_NAME_START,
    ST_FIELD_NAME,
    ST_FIELD_VALUE_START,
    ST_FIELD_VALUE,
    ST_HEAD_END
};

u32 parse_http_1_1_request(const struct bpf_mem_ptr *msg);

u32 parse_http_1_1_respond(const struct bpf_mem_ptr *msg);

static enum state __parse_request_startline(
    const struct bpf_mem_ptr *msg,
    struct bpf_mem_ptr *context,
    struct kmesh_data_node *method,
    struct kmesh_data_node *URI,
    struct kmesh_data_node *http_version)
{
    enum state current_state = ST_START;
    u32 start = 0;
    char *pstart = NULL;
    bool end_parse_startline = false;
    u32 i;
    char ch;

    for (i = 0; !end_parse_startline && i < msg->size; ++i) {
        ch = ((char *)msg->ptr)[i];
        switch (current_state) {
        case ST_START:
            if ((ch < 'A' || ch > 'Z')) {
                goto failed;
            }
            start = i;
            pstart = (char *)msg->ptr;
            current_state = ST_METHOD;
            break;
        case ST_METHOD:
            if (ch == SPACE) {
                method->value.ptr = pstart;
                method->value.size = i - start;
                (void)strncpy(method->keystring, "METHOD", METHOD_STRING_LENGTH);
                current_state = ST_SPACE_BEFORE_URI;
                break;
            }
            if (ch < 'A' || ch > 'Z')
                goto failed;
            break;
        case ST_SPACE_BEFORE_URI:
            pstart = msg->ptr + i;
            start = i;
            current_state = ST_URI;
            break;
        case ST_URI:
            if (ch == SPACE) {
                URI->value.ptr = pstart;
                URI->value.size = i - start;
                (void)strncpy(URI->keystring, "URI", URI_STRING_LENGTH);
                current_state = ST_SPACE_BEFORE_VERSION;
            }
            break;
        case ST_SPACE_BEFORE_VERSION:
            pstart = msg->ptr + i;
            start = i;
            current_state = ST_VERSION;
            break;
        case ST_VERSION:
            if (unlikely(ch == CR)) {
                http_version->value.ptr = pstart;
                http_version->value.size = i - start;
                if (strncmp((char *)http_version->value.ptr, "HTTP/1.1", strlen("HTTP/1.1")))
                    goto failed;
                (void)strncpy(http_version->keystring, "VERSION", VERSION_STRING_LENGTH);
                current_state = ST_NEW_LINE;
            }
            break;
        case ST_NEW_LINE:
            if (unlikely(ch != LF))
                goto failed;
            current_state = ST_FIELD_NAME_START;
            break;
        case ST_FIELD_NAME_START:
            context->ptr = msg->ptr + i;
            context->size = msg->size - i;
            end_parse_startline = true;
            break;
        default:
            // It's not going to get here
            break;
        }
    }

failed:
    return current_state;
}

static bool parse_request_startline(const struct bpf_mem_ptr *msg, struct bpf_mem_ptr *context)
{
    enum state current_state;
    struct kmesh_data_node *method = new_kmesh_data_node(METHOD_STRING_LENGTH);
    struct kmesh_data_node *URI = new_kmesh_data_node(URI_STRING_LENGTH);
    struct kmesh_data_node *http_version = new_kmesh_data_node(VERSION_STRING_LENGTH);

    if (IS_ERR(method) || IS_ERR(URI) || IS_ERR(http_version))
        goto failed;

    current_state = __parse_request_startline(msg, context, method, URI, http_version);
    if (current_state != ST_FIELD_NAME_START)
        goto failed;
    if (!kmesh_protocol_data_insert(method))
        delete_kmesh_data_node(&method); // the value inserted before prevails.
    if (!kmesh_protocol_data_insert(URI))
        delete_kmesh_data_node(&URI);
    if (!kmesh_protocol_data_insert(http_version))
        delete_kmesh_data_node(&http_version);

    return true;
failed:
    delete_kmesh_data_node(&method);
    delete_kmesh_data_node(&URI);
    delete_kmesh_data_node(&http_version);
    return false;
}

static enum state __parse_respose_startline(
    const struct bpf_mem_ptr *msg,
    struct bpf_mem_ptr *context,
    struct kmesh_data_node *http_version,
    struct kmesh_data_node *status_code,
    struct kmesh_data_node *reason)
{
    enum state current_state = ST_START;
    u32 start = 0;
    char *pstart = NULL;
    bool end_parse_startline = false;
    u32 i;
    char ch;

    for (i = 0; !end_parse_startline && i < msg->size; ++i) {
        ch = ((char *)msg->ptr)[i];
        switch (current_state) {
        case ST_START:
            if (ch != 'H')
                goto failed;
            start = i;
            pstart = (char *)msg->ptr;
            current_state = ST_VERSION;
            break;
        case ST_VERSION:
            if (ch == SPACE) {
                http_version->value.ptr = pstart;
                http_version->value.size = i - start;
                if (strncmp((char *)http_version->value.ptr, "HTTP/1.1", strlen("HTTP/1.1")))
                    goto failed;
                (void)strncpy(http_version->keystring, "VERSION", VERSION_STRING_LENGTH);
                current_state = ST_SPACE_BEFORE_STATUS_CODE;
            }
            break;
        case ST_SPACE_BEFORE_STATUS_CODE:
            if (ch < '0' || ch > '9')
                goto failed;
            pstart = msg->ptr + i;
            start = i;
            current_state = ST_STATUS_CODE;
            break;
        case ST_STATUS_CODE:
            if (ch < '0' || ch > '9')
                goto failed;
            if (ch == SPACE) {
                status_code->value.ptr = pstart;
                status_code->value.size = i - start;
                (void)strncpy(status_code->keystring, "STATUS", STATUS_STRING_LENGTH);
                current_state = ST_SPACE_BEFORE_REASON;
            }
            break;
        case ST_SPACE_BEFORE_REASON:
            pstart = msg->ptr + i;
            start = i;
            current_state = ST_REASON;
            break;
        case ST_REASON:
            if (ch == LF) {
                reason->value.ptr = pstart;
                reason->value.size = i - start;
                (void)strncpy(reason->keystring, "REASON", REASON_STRING_LENGTH);
                current_state = ST_NEW_LINE;
            }
            break;
        case ST_NEW_LINE:
            if (unlikely(ch != LF))
                goto failed;
            current_state = ST_FIELD_NAME_START;
            break;
        case ST_FIELD_NAME_START:
            context->ptr = msg->ptr + i;
            context->size = msg->size - i;
            end_parse_startline = true;
            break;
        default:
            // It's not going to get here
            break;
        }
    }
failed:
    return current_state;
}

static bool parse_respose_startline(const struct bpf_mem_ptr *msg, struct bpf_mem_ptr *context)
{
    enum state current_state;
    struct kmesh_data_node *http_version = new_kmesh_data_node(VERSION_STRING_LENGTH);
    struct kmesh_data_node *status_code = new_kmesh_data_node(STATUS_STRING_LENGTH);
    struct kmesh_data_node *reason = new_kmesh_data_node(REASON_STRING_LENGTH);

    if (IS_ERR(http_version) || IS_ERR(status_code) || IS_ERR(reason))
        goto failed;

    current_state = __parse_respose_startline(msg, context, http_version, status_code, reason);
    if (current_state != ST_FIELD_NAME_START)
        goto failed;
    if (!kmesh_protocol_data_insert(http_version))
        delete_kmesh_data_node(&http_version);
    if (!kmesh_protocol_data_insert(status_code))
        delete_kmesh_data_node(&status_code);
    if (!kmesh_protocol_data_insert(reason))
        delete_kmesh_data_node(&reason);

    return true;
failed:
    delete_kmesh_data_node(&http_version);
    delete_kmesh_data_node(&status_code);
    delete_kmesh_data_node(&reason);
    return false;
}

static bool parse_header(struct bpf_mem_ptr *context)
{
    enum state current_state = ST_FIELD_NAME_START;
    bool head_end = false;
    u32 field_name_begin_position = 0;
    u32 field_name_end_position = 0;
    u32 field_value_begin_position = 0;
    u32 field_value_end_position = 0;
    u32 i;
    char ch;
    struct kmesh_data_node *old_field = NULL;
    struct kmesh_data_node *new_field = NULL;
    for (i = 0; !head_end && i < context->size; ++i) {
        ch = ((char *)context->ptr)[i];
        switch (current_state) {
        case ST_FIELD_NAME_START:
            if (ch == FIELD_SPLIT)
                return false;
            if (ch == CR) {
                current_state = ST_HEAD_END;
                break;
            }
            if (ch == SPACE)
                continue;
            field_name_begin_position = i;
            field_name_end_position = i;
            current_state = ST_FIELD_NAME;
            break;
        case ST_FIELD_NAME:
            if (ch != SPACE && ch != FIELD_SPLIT)
                field_name_end_position = i;
            if (ch == FIELD_SPLIT)
                current_state = ST_FIELD_VALUE_START;
            break;
        case ST_FIELD_VALUE_START:
            if (ch == SPACE)
                continue;
            field_value_begin_position = i;
            field_value_end_position = i;
            if (ch == CR)
                current_state = ST_NEW_LINE;
            else
                current_state = ST_FIELD_VALUE;
            break;
        case ST_FIELD_VALUE:
            if (ch != SPACE)
                field_value_end_position = i;

            if (unlikely(ch == CR))
                current_state = ST_NEW_LINE;
            break;
        case ST_NEW_LINE:
            if (unlikely(ch != LF))
                return false;
            if (field_name_end_position < field_name_begin_position)
                return false;
            if (field_value_end_position < field_value_begin_position)
                return false;
            new_field = new_kmesh_data_node(field_name_end_position - field_name_begin_position + 2);
            if (IS_ERR(new_field))
                return false;
            (void)strncpy(
                new_field->keystring,
                ((char *)context->ptr) + field_name_begin_position,
                field_name_end_position - field_name_begin_position + 1);
            old_field = kmesh_protocol_data_search(new_field->keystring);
            if (unlikely(old_field)) {
                old_field->value.ptr = context->ptr + field_value_begin_position;
                old_field->value.size = field_value_end_position - field_value_begin_position;
                delete_kmesh_data_node(&new_field);
                old_field = NULL;
            } else {
                new_field->value.ptr = context->ptr + field_value_begin_position;
                new_field->value.size = field_value_end_position - field_value_begin_position;

                if (!kmesh_protocol_data_insert(new_field)) {
                    delete_kmesh_data_node(&new_field);
                    break;
                }
                new_field = NULL;
            }
            current_state = ST_FIELD_NAME_START;
            break;
        case ST_HEAD_END:
            if (ch != LF)
                return false;
            head_end = true;
            break;
        default:
            // It's not going to get here
            break;
        }
    }
    if (current_state != ST_HEAD_END)
        return false;

    return true;
}

u32 parse_http_1_1_request(const struct bpf_mem_ptr *msg)
{
    struct bpf_mem_ptr context = {0};
    u32 ret = 0;
    if (parse_request_startline(msg, &context) == false) {
        kmesh_protocol_data_clean_all();
        return PROTO_UNKNOW;
    }

    // Parse the rest of the header
    if (parse_header(&context) == false) {
        kmesh_protocol_data_clean_all();
        return PROTO_UNKNOW;
    }

    SET_RET_PROTO_TYPE(ret, PROTO_HTTP_1_1);
    SET_RET_MSG_TYPE(ret, MSG_REQUEST);

    return ret;
}

u32 parse_http_1_1_respond(const struct bpf_mem_ptr *msg)
{
    struct bpf_mem_ptr context = {0};
    u32 ret = 0;
    if (parse_respose_startline(msg, &context) == false) {
        kmesh_protocol_data_clean_all();
        return PROTO_UNKNOW;
    }

    // Parse the rest of the header
    if (parse_header(&context) == false) {
        kmesh_protocol_data_clean_all();
        return PROTO_UNKNOW;
    }

    SET_RET_PROTO_TYPE(ret, PROTO_HTTP_1_1);
    SET_RET_MSG_TYPE(ret, MSG_FINAL_RESPONSE);

    return ret;
}

static struct msg_protocol http_1_1_request = {
    .parse_protocol_msg = parse_http_1_1_request,
};

static struct msg_protocol http_1_1_respose = {
    .parse_protocol_msg = parse_http_1_1_respond,
};

static void register_http_1_1_request(void)
{
    list_add_tail(&http_1_1_request.list, &g_protocol_list_head);
}

static void register_http_1_1_repose(void)
{
    list_add_tail(&http_1_1_respose.list, &g_protocol_list_head);
}

int __init kmesh_register_http_1_1_init(void)
{
    register_http_1_1_request();
    register_http_1_1_repose();

    return 0;
}
