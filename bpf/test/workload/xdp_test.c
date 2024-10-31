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

#include "common.h"

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
        test_log("Packet size too large: %zu > %u", size, max_data_sz);
        return -1;
    }

    // Allocate memory for the full frame
    void *data;
    size_t frame_size = headroom + size + tailroom;
    if (posix_memalign(&data, getpagesize(), frame_size) != 0) {
        test_log("Failed to allocate memory for test data");
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

    test_log("Debug info:");
    test_log("  frame_size: %zu", frame_size);
    test_log("  headroom: %u", headroom);
    test_log("  data_size: %zu", size);
    test_log("  tailroom: %u", tailroom);
    test_log("  hard_start: %p", xdp.data_hard_start);
    test_log("  data: %p", xdp.data);
    test_log("  data_end: %p", xdp.data_end);
    test_log("  frame_sz: %u", xdp.frame_sz);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = data + headroom,
        .data_out = data + headroom,
        .data_size_in = size,
        .data_size_out = size,
        // XDP programs don't use ctx_in/ctx_out according to kernel code
        .ctx_in = NULL,
        .ctx_out = NULL,
        .ctx_size_in = 0,
        .ctx_size_out = 0,
        .repeat = 1,
    };

    int ret = bpf_prog_test_run_opts(prog_fd, &opts);
    if (ret != 0) {
        test_log("bpf_prog_test_run_opts failed: %d (errno: %d - %s)", 
               ret, errno, strerror(errno));
        test_log("Data size: %u, Frame size: %zu", 
               opts.data_size_in, frame_size);
        test_log("Prog FD: %d", prog_fd);
        test_log("Retval: %d", opts.retval);
    } else {
        test_log("Test run successful, retval: %d", opts.retval);
    }

    free(data);
    memcpy(packet, opts.data_out, opts.data_size_out);
    return ret;
}

void bpf_offload() {
    xdp_bpf__destroy(skel);
}

void test_packet_parsing() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Set minimum packet size
    size_t min_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    test_assert(PACKET_SIZE >= min_size, "PACKET_SIZE too small");

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

    test_log("Packet size: %u", PACKET_SIZE);
    test_log("Headers size: %u", min_size);

    int err = run_xdp_test(packet, PACKET_SIZE);
    test_log("err = %d", err);
    test_assert(err == 0, "run_xdp_test failed");
}

void bpf_load() {
    int err;
    
    skel = xdp_bpf__open();
    test_assert(skel != NULL, "Failed to open BPF skeleton");

    // Set XDP program type
    bpf_program__set_type(skel->progs.xdp_shutdown, BPF_PROG_TYPE_XDP);
    
    err = xdp_bpf__load(skel);
    test_assert(err == 0, "Failed to load BPF skeleton");

    prog_fd = bpf_program__fd(skel->progs.xdp_shutdown);
    test_assert(prog_fd >= 0, "Failed to get program FD");

    // Get program type and expected test parameters
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    test_assert(err == 0, "Failed to get program info");

    test_log("Successfully loaded XDP program, prog_fd = %d, type = %u", prog_fd, info.type);
}

void test_ip_version_check() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

    eth->h_proto = htons(ETH_P_IP);
    ip->version = 5;  // Invalid IP version

    int err = run_xdp_test(packet, PACKET_SIZE);
    test_assert(err == 0, "run_xdp_test failed");
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
    test_assert(err == 0, "run_xdp_test failed");
}

void test_connection_shutdown() {
    unsigned char packet[PACKET_SIZE] = {0};
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Set minimum packet size
    size_t min_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    test_assert(PACKET_SIZE >= min_size, "PACKET_SIZE too small");

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
    __u32 value = AUTH_FORBID;  // Use AUTH_FORBID value
    
    // Update the map
    int err = bpf_map_update_elem(bpf_map__fd(skel->maps.map_of_auth), &tuple, &value, BPF_ANY);
    test_assert(err == 0, "Failed to update map");

    // Log test details
    test_log("Testing connection shutdown:");
    test_log("  Source IP: %s", inet_ntoa((struct in_addr){.s_addr = ip->saddr}));
    test_log("  Dest IP: %s", inet_ntoa((struct in_addr){.s_addr = ip->daddr}));
    test_log("  Source Port: %d", ntohs(tcp->source));
    test_log("  Dest Port: %d", ntohs(tcp->dest));
    test_log("  Map value: %u", value);

    // Run the XDP program 
    int err1 = run_xdp_test(packet, PACKET_SIZE);
    test_assert(err1 == 0, "XDP test failed");

    // Check if the packet was modified correctly
    struct tcphdr *modified_tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    test_log("TCP flags after XDP:");
    test_log("  RST: %d", modified_tcp->rst);
    test_log("  SYN: %d", modified_tcp->syn);
    test_log("  FIN: %d", modified_tcp->fin);
    test_log("  PSH: %d", modified_tcp->psh);
    test_log("  ACK: %d", modified_tcp->ack);

    // Verify that RST flag was set
    test_assert(modified_tcp->rst == 1, "RST flag not set");
    test_assert(modified_tcp->syn == 0, "SYN flag not cleared");  // SYN should be cleared
    test_assert(modified_tcp->fin == 0, "FIN flag not cleared");  // FIN should be cleared
    test_assert(modified_tcp->psh == 0, "PSH flag not cleared");  // PSH should be cleared
    test_assert(modified_tcp->ack == 0, "ACK flag not cleared");  // ACK should be cleared

    // Clean up the map entry
    bpf_map_delete_elem(bpf_map__fd(skel->maps.map_of_auth), &tuple);
}

int main() {
    test_init("xdp_test");
    
    TEST("BPF Program Load", bpf_load);
    TEST("Packet Parsing", test_packet_parsing);
    TEST("IP Version Check", test_ip_version_check);
    TEST("Tuple Extraction", test_tuple_extraction);
    TEST("Connection Shutdown", test_connection_shutdown);
    TEST("BPF Program Cleanup", bpf_offload);

    test_finish();
    return current_suite.failed_count > 0 ? 1 : 0;
}