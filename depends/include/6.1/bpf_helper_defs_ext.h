static void *(*bpf_strncpy)(char *dst, __u32 dst_size, char *src) = (void *)210;
static void *(*bpf_strnstr)(void *s1, void *s2, __u32 size) = (void *)211;
static __u64 (*bpf_strnlen)(char *buff, __u32 size) = (void *)212;
static long(*bpf_parse_header_msg)(struct bpf_mem_ptr *msg) = (void *)213;
static void *(*bpf_get_msg_header_element)(void *name) = (void *)214;
