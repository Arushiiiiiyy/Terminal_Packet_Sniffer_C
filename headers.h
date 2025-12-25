//#########LLM GENERATED CODE BEGINS#########
#ifndef HEADERS_H
#define HEADERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>

#define MAX_PACKETS 10000
#define SNAP_LEN 65535
#define TIMEOUT_MS 1000

// Packet storage structure
typedef struct stored_packet {
    int id;
    struct timeval timestamp;
    int length;
    int captured_length;
    u_char *data;
    struct stored_packet *next;
} stored_packet_t;

// Session structure
typedef struct {
    stored_packet_t *head;
    stored_packet_t *tail;
    int packet_count;
    int filter_type;  // 0=none, 1=HTTP, 2=HTTPS, 3=DNS, 4=ARP, 5=TCP, 6=UDP
} session_t;

// Global variables
extern volatile int keep_sniffing;
extern volatile sig_atomic_t interrupted;
extern session_t *current_session;
extern int packet_counter;
extern pcap_t *global_pcap_handle;

// Function declarations
void sniff_all(const char *device_name);
void sniff_filtered(const char *device_name, int filter_type);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void print_packet_summary(int id, struct timeval timestamp, int length, const u_char *packet);
void print_packet_summary_with_linktype(int id, struct timeval timestamp, int length, const u_char *packet, int datalink_type);
void decode_ethernet(const u_char *packet, int total_length);
void decode_loopback(const u_char *packet, int total_length);
void decode_raw_ip(const u_char *packet, int total_length);
void decode_ipv4(const u_char *packet, int packet_length);
void decode_ipv6(const u_char *packet, int packet_length);
void decode_arp(const u_char *packet);
void decode_tcp(const u_char *packet, int offset, int packet_length);
void decode_udp(const u_char *packet, int offset, int packet_length);
void decode_icmpv6(const u_char *packet, int offset, int packet_length);
void decode_payload(const u_char *packet, int offset, int total_len, int port, int packet_length);
void print_hex_dump(const u_char *data, int len, int max_len);
void print_hex_ascii(const u_char *data, int len);
void store_packet(int id, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void free_session(session_t *session);
void inspect_session(void);
void show_detailed_packet(stored_packet_t *pkt);
void signal_handler(int sig);
void cleanup_and_exit(void);
const char* get_port_name(int port);
const char* get_ethertype_name(uint16_t type);
int should_capture_packet(const u_char *packet, int len, int filter_type);

#endif