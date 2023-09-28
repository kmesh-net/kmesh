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

static char * (*bpf_strchr)(void *s, int c) = (void *) 156;
static char * (*bpf_strstr)(void *s1, void *s2) = (void *) 157;
static int (*bpf_strcmp)(void *s1, void *s2) = (void *) 158;
static int (*bpf_mem_replace)(struct bpf_mem_ptr *mem, struct bpf_mem_ptr *old, struct bpf_mem_ptr *new) = (void *) 159;
static int (*bpf_strcpy)(char *dst, __u32 dst_size, char *src) = (void *) 160;
static char * (*bpf_strnstr)(void *dst, void *src, __u32 copy_size) = (void *) 161;

/*
 * bpf_parse_header_msg
 *
 *      Parses the input msg information into the corresponding key-value
 *      format and saves the format in the kernel. The specific
 *      implementation is implemented by user-defined .ko.
 *
 * Returns
 *      User-defined structure, such as the protocol type.
 */
static int (*bpf_parse_header_msg)(struct bpf_mem_ptr *msg) = (void *) 162;

/*
 * bpf_get_msg_header_element
 *
 *      Used with *bpf_parse_header_msg* to obtain the corresponding key
 *      from the data structure parsed by *bpf_parse_header_msg*.
 *
 * Returns
 *      Contains a pointer to the data and the length of the data.
 */

static void *(*bpf_get_msg_header_element)(char *name) = (void *) 163;

/*
 * bpf_strlen
 *
 *      Obtains the length of a character string.
 *
 * Returns
 *      Length of the string.
 */

static int (*bpf_strlen)(char *buff) = (void *) 164;

/*
 * bpf_strncmp
 *
 *      Do strncmp() between **s1** and **s2**. **s1** doesn't need
 *      to be null-terminated and **s1_sz** is the maximum storage
 *      size of **s1**. **s2** must be a read-only string.
 *
 * Returns
 *      An integer less than, equal to, or greater than zero
 *      if the first **s1_sz** bytes of **s1** is found to be
 *      less than, to match, or be greater than **s2**.
 */
static long (*bpf_strncmp)(const char *s1, __u32 s1_sz, const char *s2) = (void *) 165;
