#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include "xdp_test.skel.h"
#include <asm/unistd.h>

// #include "common.h"

// Add missing includes and definitions
#include <unistd.h>
#include <linux/if_xdp.h>
#include <linux/if.h>
#include <linux/bpf.h>

#define XDP_PACKET_HEADROOM 256
#define SKB_DATA_ALIGN(len) (((len) + (64 - 1)) & ~(64 - 1))
#define AUTH_PASS   0
#define AUTH_FORBID 1

// Define skb_shared_info structure (simplified version)
struct skb_shared_info {
    unsigned char pad[256];  // Simplified version
};

// Define xdp_buff structure
struct xdp_buff {
    void *data;
    void *data_end;
    void *data_meta;
    void *data_hard_start;
    unsigned int frame_sz;
};

#define PACKET_SIZE 100

struct xdp_bpf *skel;
int prog_fd;

static int run_xdp_test(void *packet, size_t size) {
    // Constants from kernel implementation
    unsigned int headroom = XDP_PACKET_HEADROOM;  // 256
    unsigned int tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
    unsigned int max_data_sz = 4096 - headroom - tailroom;

    if (size > max_data_sz) {
        printf("Packet size too large: %zu > %u\n", size, max_data_sz);
        return -1;
    }

    // Allocate memory for the full frame
    void *data;
    size_t frame_size = headroom + size + tailroom;  // Changed: use actual size instead of max_data_sz
    if (posix_memalign(&data, getpagesize(), frame_size) != 0) {
        printf("Failed to allocate memory for test data\n");
        return -1;
    }

    // Initialize the memory to zero
    memset(data, 0, frame_size);
    
    // Copy packet data to the correct location (after headroom)
    memcpy(data + headroom, packet, size);

    struct xdp_buff xdp = {
        .data_hard_start = data,
        .data = data + headroom,
        .data_meta = data + headroom,
        .data_end = data + headroom + size,
        .frame_sz = frame_size,
    };

    printf("Debug info:\n");
    printf("  frame_size: %zu\n", frame_size);
    printf("  headroom: %u\n", headroom);
    printf("  data_size: %zu\n", size);
    printf("  tailroom: %u\n", tailroom);
    printf("  hard_start: %p\n", xdp.data_hard_start);
    printf("  data: %p\n", xdp.data);
    printf("  data_end: %p\n", xdp.data_end);
    printf("  frame_sz: %u\n", xdp.frame_sz);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = data,
        .data_out = data,
        .data_size_in = size + headroom,  // Changed: only include headroom + actual data
        .data_size_out = size + headroom,
        // XDP programs don't use ctx_in/ctx_out according to kernel code
        .ctx_in = NULL,
        .ctx_out = NULL,
        .ctx_size_in = 0,
        .ctx_size_out = 0,
        .repeat = 1,
    };

    int ret = bpf_prog_test_run_opts(prog_fd, &opts);
    if (ret != 0) {
        printf("bpf_prog_test_run_opts failed: %d (errno: %d - %s)\n", 
               ret, errno, strerror(errno));
        printf("Data size: %u, Frame size: %zu\n", 
               opts.data_size_in, frame_size);
        printf("Prog FD: %d\n", prog_fd);
        printf("Retval: %d\n", opts.retval);
    } else {
        printf("Test run successful, retval: %d\n", opts.retval);
    }

    free(data);
    return ret;
}

void test_finish() {
    xdp_bpf__destroy(skel);
}


void test_packet_parsing() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Set minimum packet size
    size_t min_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (PACKET_SIZE < min_size) {
        printf("PACKET_SIZE too small, needs at least %zu bytes\n", min_size);
        assert(0);
    }

    // Fill in packet headers
    eth->h_proto = htons(ETH_P_IP);
    memset(eth->h_source, 0x12, ETH_ALEN);
    memset(eth->h_dest, 0x34, ETH_ALEN);
    
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->daddr = htonl(0x08080808); // 8.8.8.8
    ip->saddr = htonl(0x0A000001); // 10.0.0.1
    
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5; // 20 bytes TCP header

    printf("Packet size: %zu\n", PACKET_SIZE);
    printf("Headers size: %zu\n", min_size);

    int err = run_xdp_test(packet, PACKET_SIZE);
    printf("err = %d\n", err);
    assert(err == 0);
}

void test_init() {
    int err;
    
    skel = xdp_bpf__open();
    if (!skel) {
        printf("Failed to open BPF skeleton\n");
        assert(0);
    }

    // 修改 XDP 程序的类型
    bpf_program__set_type(skel->progs.xdp_shutdown, BPF_PROG_TYPE_XDP);
    
    err = xdp_bpf__load(skel);
    if (err) {
        printf("Failed to load BPF skeleton: %d\n", err);
        assert(0);
    }

    prog_fd = bpf_program__fd(skel->progs.xdp_shutdown);
    if (prog_fd < 0) {
        printf("Failed to get program FD: %d\n", prog_fd);
        assert(0);
    }

    // 获取程序类型和预期的测试参数
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err) {
        printf("Failed to get program info: %d\n", err);
        assert(0);
    }

    printf("Successfully loaded XDP program, prog_fd = %d, type = %u\n", prog_fd, info.type);
}

void test_ip_version_check() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    eth->h_proto = htons(ETH_P_IP);
    ip->version = 5;  // Invalid IP version

    int err = run_xdp_test(packet, PACKET_SIZE);
    assert(err == 0);
}

void test_tuple_extraction() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    eth->h_proto = htons(ETH_P_IP);
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.1");
    ip->daddr = inet_addr("192.168.1.2");
    tcp->source = htons(12345);
    tcp->dest = htons(80);

    int err = run_xdp_test(packet, PACKET_SIZE);
    assert(err == 0);
}

void test_connection_shutdown() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Set minimum packet size
    size_t min_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (PACKET_SIZE < min_size) {
        printf("PACKET_SIZE too small, needs at least %zu bytes\n", min_size);
        assert(0);
    }

    // Fill in ethernet header
    eth->h_proto = htons(ETH_P_IP);
    memset(eth->h_source, 0x12, ETH_ALEN);
    memset(eth->h_dest, 0x34, ETH_ALEN);
    
    // Fill in IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->saddr = inet_addr("192.168.1.1");
    ip->daddr = inet_addr("192.168.1.2");
    
    // Fill in TCP header
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5;  // 20 bytes TCP header
    tcp->syn = 1;   // SYN packet
    tcp->rst = 0;   // Make sure RST is not set initially

    // Add the connection to the auth map to simulate a connection that should be shut down
    struct bpf_sock_tuple tuple = {
        .ipv4 = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .sport = tcp->source,
            .dport = tcp->dest,
        },
    };
    __u32 value = AUTH_FORBID;  // 使用 AUTH_FORBID 值
    
    // Update the map
    int err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_of_auth), &tuple, &value, BPF_ANY);
    if (err) {
        printf("Failed to update map: %d (errno: %d - %s)\n", err, errno, strerror(errno));
        assert(0);
    }

    printf("Testing connection shutdown:\n");
    printf("  Source IP: %s\n", inet_ntoa((struct in_addr){.s_addr = ip->saddr}));
    printf("  Dest IP: %s\n", inet_ntoa((struct in_addr){.s_addr = ip->daddr}));
    printf("  Source Port: %d\n", ntohs(tcp->source));
    printf("  Dest Port: %d\n", ntohs(tcp->dest));
    printf("  Map value: %u\n", value);

    // Run the XDP program 
    int err1 = run_xdp_test(packet, PACKET_SIZE);
    if (err1 != 0) {
        printf("XDP test failed: %d\n", err);
        assert(0);
    }

    // Check if the packet was modified correctly
    struct tcphdr *modified_tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    printf("TCP flags after XDP:\n");
    printf("  RST: %d\n", modified_tcp->rst);
    printf("  SYN: %d\n", modified_tcp->syn);
    printf("  FIN: %d\n", modified_tcp->fin);
    printf("  PSH: %d\n", modified_tcp->psh);
    printf("  ACK: %d\n", modified_tcp->ack);

    // Verify that RST flag was set
    assert(modified_tcp->rst == 1);
    assert(modified_tcp->syn == 0);  // SYN should be cleared
    assert(modified_tcp->fin == 0);  // FIN should be cleared
    assert(modified_tcp->psh == 0);  // PSH should be cleared
    assert(modified_tcp->ack == 0);  // ACK should be cleared

    // Clean up the map entry
    bpf_map_delete_elem(bpf_map__fd(skel->maps.map_of_auth), &tuple);
}

int main() {
    test_init();

    test_packet_parsing();
    test_ip_version_check();
    test_tuple_extraction();
    // test_connection_shutdown();

    test_finish();
    printf("All tests passed!\n");
    return 0;
}