//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

void print_packet_summary(int id, struct timeval timestamp, int length, const u_char *packet) {
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06d | Length: %d bytes\n", 
           id, timestamp.tv_sec, timestamp.tv_usec, length);
    
    // Decode Ethernet layer (assuming Ethernet - default behavior)
    decode_ethernet(packet, length);
}

void print_packet_summary_with_linktype(int id, struct timeval timestamp, int length, const u_char *packet, int datalink_type) {
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06d | Length: %d bytes\n", 
           id, timestamp.tv_sec, timestamp.tv_usec, length);
    
    // Decode based on link-layer type
    switch (datalink_type) {
        case DLT_EN10MB:  // Ethernet
            decode_ethernet(packet, length);
            break;
            
        case DLT_NULL:    // BSD loopback encapsulation (lo0 on macOS)
        case DLT_LOOP:    // OpenBSD loopback encapsulation
            decode_loopback(packet, length);
            break;
            
        case DLT_RAW:     // Raw IP (no link layer)
            decode_raw_ip(packet, length);
            break;
            
        default:
            printf("L2: Unsupported link-layer type (%d)\n", datalink_type);
            // Try to decode as Ethernet anyway
            decode_ethernet(packet, length);
            break;
    }
}

void decode_loopback(const u_char *packet, int total_length) {
    // Loopback has a 4-byte header indicating the protocol family
    // On macOS/BSD: network byte order
    // Format: 4-byte protocol family (AF_INET = 2, AF_INET6 = 30 on BSD)
    
    if (total_length < 4) {
        printf("L2 (Loopback): Packet too short\n");
        return;
    }
    
    // Read the protocol family (4 bytes, network byte order on macOS)
    uint32_t protocol_family;
    memcpy(&protocol_family, packet, 4);
    
    // On macOS, it's in host byte order, but let's check both ways
    uint32_t pf_host = protocol_family;
    uint32_t pf_net = ntohl(protocol_family);
    
    printf("L2 (Loopback): ");
    
    // AF_INET = 2, AF_INET6 = 30 on BSD/macOS
    const u_char *ip_packet = packet + 4;
    int ip_length = total_length - 4;
    
    // Check the IP version in the first byte
    if (ip_length > 0) {
        uint8_t version = (ip_packet[0] >> 4) & 0x0F;
        
        if (version == 4) {
            printf("Protocol: IPv4\n");
            decode_ipv4(ip_packet, ip_length);
        } else if (version == 6) {
            printf("Protocol: IPv6\n");
            decode_ipv6(ip_packet, ip_length);
        } else {
            printf("Unknown Protocol (Version: %d, PF: %u/%u)\n", version, pf_host, pf_net);
        }
    } else {
        printf("Empty packet\n");
    }
}

void decode_raw_ip(const u_char *packet, int total_length) {
    printf("L2 (Raw IP): No link layer\n");
    
    if (total_length < 1) {
        printf("Packet too short\n");
        return;
    }
    
    // Check IP version from first nibble
    uint8_t version = (packet[0] >> 4) & 0x0F;
    
    if (version == 4) {
        decode_ipv4(packet, total_length);
    } else if (version == 6) {
        decode_ipv6(packet, total_length);
    } else {
        printf("Unknown IP version: %d\n", version);
    }
}

void decode_ethernet(const u_char *packet, int total_length) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1],
           eth_header->ether_dhost[2], eth_header->ether_dhost[3],
           eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    printf("Src MAC: %02X:%02X:%02X:%02X:%02X:%02X |\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1],
           eth_header->ether_shost[2], eth_header->ether_shost[3],
           eth_header->ether_shost[4], eth_header->ether_shost[5]);
    
    uint16_t ether_type = ntohs(eth_header->ether_type);
    printf("    EtherType: %s (0x%04X)\n", get_ethertype_name(ether_type), ether_type);
    
    // Decode Layer 3 based on EtherType
    switch (ether_type) {
        case ETHERTYPE_IP:
            decode_ipv4(packet + sizeof(struct ether_header), total_length - sizeof(struct ether_header));
            break;
        case ETHERTYPE_IPV6:
            decode_ipv6(packet + sizeof(struct ether_header), total_length - sizeof(struct ether_header));
            break;
        case ETHERTYPE_ARP:
            decode_arp(packet + sizeof(struct ether_header));
            break;
    }
}

void decode_ipv4(const u_char *packet, int packet_length) {
    struct ip *ip_header = (struct ip *)packet;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    
    const char *protocol;
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: protocol = "TCP"; break;
        case IPPROTO_UDP: protocol = "UDP"; break;
        case IPPROTO_ICMP: protocol = "ICMP"; break;
        default: protocol = "Unknown"; break;
    }
    
    // Extract TOS/DSCP (Traffic Class equivalent in IPv4)
    uint8_t traffic_class = ip_header->ip_tos;
    
    // Calculate payload length (Total Length - Header Length)
    uint16_t total_length = ntohs(ip_header->ip_len);
    uint16_t header_length = ip_header->ip_hl * 4;
    uint16_t payload_length = total_length - header_length;
    
    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
           src_ip, dst_ip, protocol, ip_header->ip_p, ip_header->ip_ttl);
    printf("    Traffic Class: %d | ID: 0x%04X | Payload Length: %d | Header Length: %d bytes\n",
           traffic_class, ntohs(ip_header->ip_id), payload_length, header_length);
    
    // Decode flags
    int flags = ntohs(ip_header->ip_off);
    if (flags & IP_DF) printf("    Flags: [DF]\n");
    if (flags & IP_MF) printf("    Flags: [MF]\n");
    
    // Decode Layer 4
    int ip_header_len = ip_header->ip_hl * 4;
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            decode_tcp(packet, ip_header_len, packet_length);
            break;
        case IPPROTO_UDP:
            decode_udp(packet, ip_header_len, packet_length);
            break;
    }
}

void decode_ipv6(const u_char *packet, int packet_length) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)packet;
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    
    // Extract IPv6 header fields
    uint8_t next_header = ip6_header->ip6_nxt;
    uint8_t hop_limit = ip6_header->ip6_hlim;
    uint16_t payload_length = ntohs(ip6_header->ip6_plen);
    
    // Extract traffic class and flow label from ip6_flow
    // ip6_flow is in network byte order and contains: version(4) + traffic class(8) + flow label(20)
    uint32_t flow_info = ntohl(ip6_header->ip6_flow);
    uint8_t traffic_class = (flow_info >> 20) & 0xFF;
    uint32_t flow_label = flow_info & 0x000FFFFF;
    
    const char *next_header_name;
    switch (next_header) {
        case IPPROTO_TCP: next_header_name = "TCP"; break;
        case IPPROTO_UDP: next_header_name = "UDP"; break;
        case IPPROTO_ICMPV6: next_header_name = "ICMPv6"; break;
        default: next_header_name = "Unknown"; break;
    }
    
    printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
           src_ip, dst_ip, next_header_name, next_header, hop_limit);
    printf("    Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
           traffic_class, flow_label, payload_length);
    
    // Decode Layer 4
    switch (next_header) {
        case IPPROTO_TCP:
            decode_tcp(packet, sizeof(struct ip6_hdr), packet_length);
            break;
        case IPPROTO_UDP:
            decode_udp(packet, sizeof(struct ip6_hdr), packet_length);
            break;
        case IPPROTO_ICMPV6:
            decode_icmpv6(packet, sizeof(struct ip6_hdr), packet_length);
            break;
    }
}

void decode_arp(const u_char *packet) {
    struct arphdr *arp_header = (struct arphdr *)packet;
    
    const char *op_str;
    uint16_t op = ntohs(arp_header->ar_op);
    switch (op) {
        case ARPOP_REQUEST: op_str = "Request"; break;
        case ARPOP_REPLY: op_str = "Reply"; break;
        default: op_str = "Unknown"; break;
    }
    
    // Get ARP payload
    const u_char *arp_payload = packet + sizeof(struct arphdr);
    
    // Extract addresses (assuming Ethernet and IPv4)
    if (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER && 
        ntohs(arp_header->ar_pro) == ETHERTYPE_IP) {
        
        u_char sender_mac[6], target_mac[6];
        struct in_addr sender_ip, target_ip;
        
        memcpy(sender_mac, arp_payload, 6);
        memcpy(&sender_ip, arp_payload + 6, 4);
        memcpy(target_mac, arp_payload + 10, 6);
        memcpy(&target_ip, arp_payload + 14, 4);
        
        char sender_ip_str[INET_ADDRSTRLEN], target_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_ip, sender_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &target_ip, target_ip_str, INET_ADDRSTRLEN);
        
        printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
               op_str, op, sender_ip_str, target_ip_str);
        printf("    Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
               sender_mac[0], sender_mac[1], sender_mac[2],
               sender_mac[3], sender_mac[4], sender_mac[5]);
        printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               target_mac[0], target_mac[1], target_mac[2],
               target_mac[3], target_mac[4], target_mac[5]);
        printf("    HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
               ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro),
               arp_header->ar_hln, arp_header->ar_pln);
    }
}

void decode_tcp(const u_char *packet, int offset, int packet_length) {
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + offset);
    
    // macOS uses th_sport/th_dport, Linux uses source/dest
    #ifdef __APPLE__
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    #else
    uint16_t src_port = ntohs(tcp_header->source);
    uint16_t dst_port = ntohs(tcp_header->dest);
    #endif
    
    printf("L4 (TCP): Src Port: %d%s | Dst Port: %d%s | ",
           src_port, get_port_name(src_port),
           dst_port, get_port_name(dst_port));
    
    // macOS uses th_seq/th_ack, Linux uses seq/ack_seq
    #ifdef __APPLE__
    printf("Seq: %u | Ack: %u | ",
           ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack));
    #else
    printf("Seq: %u | Ack: %u | ",
           ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq));
    #endif
    
    // Decode flags - macOS uses th_flags, Linux uses individual bit fields
    printf("Flags: [");
    int first = 1;
    #ifdef __APPLE__
    if (tcp_header->th_flags & TH_FIN) { printf("%sFIN", first ? "" : ","); first = 0; }
    if (tcp_header->th_flags & TH_SYN) { printf("%sSYN", first ? "" : ","); first = 0; }
    if (tcp_header->th_flags & TH_RST) { printf("%sRST", first ? "" : ","); first = 0; }
    if (tcp_header->th_flags & TH_PUSH) { printf("%sPSH", first ? "" : ","); first = 0; }
    if (tcp_header->th_flags & TH_ACK) { printf("%sACK", first ? "" : ","); first = 0; }
    if (tcp_header->th_flags & TH_URG) { printf("%sURG", first ? "" : ","); first = 0; }
    #else
    if (tcp_header->fin) { printf("%sFIN", first ? "" : ","); first = 0; }
    if (tcp_header->syn) { printf("%sSYN", first ? "" : ","); first = 0; }
    if (tcp_header->rst) { printf("%sRST", first ? "" : ","); first = 0; }
    if (tcp_header->psh) { printf("%sPSH", first ? "" : ","); first = 0; }
    if (tcp_header->ack) { printf("%sACK", first ? "" : ","); first = 0; }
    if (tcp_header->urg) { printf("%sURG", first ? "" : ","); first = 0; }
    #endif
    printf("]\n");
    
    // macOS uses th_win/th_sum/th_off, Linux uses window/check/doff
    #ifdef __APPLE__
    printf("    Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
           ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum),
           tcp_header->th_off * 4);
    
    // Decode payload
    int tcp_header_len = tcp_header->th_off * 4;
    #else
    printf("    Window: %d | Checksum: 0x%04X | Header Length: %d bytes\n",
           ntohs(tcp_header->window), ntohs(tcp_header->check),
           tcp_header->doff * 4);
    
    // Decode payload
    int tcp_header_len = tcp_header->doff * 4;
    #endif
    int total_offset = offset + tcp_header_len;
    int payload_len = packet_length - total_offset;
    
    if (payload_len > 0) {
        decode_payload(packet, total_offset, payload_len, dst_port, packet_length);
    }
}

void decode_udp(const u_char *packet, int offset, int packet_length) {
    struct udphdr *udp_header = (struct udphdr *)(packet + offset);
    
    // macOS uses uh_sport/uh_dport, Linux uses source/dest
    #ifdef __APPLE__
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);
    #else
    uint16_t src_port = ntohs(udp_header->source);
    uint16_t dst_port = ntohs(udp_header->dest);
    #endif
    
    printf("L4 (UDP): Src Port: %d%s | Dst Port: %d%s | ",
           src_port, get_port_name(src_port),
           dst_port, get_port_name(dst_port));
    
    // macOS uses uh_ulen/uh_sum, Linux uses len/check
    #ifdef __APPLE__
    printf("Length: %d | Checksum: 0x%04X\n",
           ntohs(udp_header->uh_ulen), ntohs(udp_header->uh_sum));
    
    // Decode payload
    int udp_header_len = sizeof(struct udphdr);
    int total_offset = offset + udp_header_len;
    int payload_len = ntohs(udp_header->uh_ulen) - udp_header_len;
    #else
    printf("Length: %d | Checksum: 0x%04X\n",
           ntohs(udp_header->len), ntohs(udp_header->check));
    
    // Decode payload
    int udp_header_len = sizeof(struct udphdr);
    int total_offset = offset + udp_header_len;
    int payload_len = ntohs(udp_header->len) - udp_header_len;
    #endif
    
    if (payload_len > 0) {
        decode_payload(packet, total_offset, payload_len, dst_port, packet_length);
    }
}

void decode_icmpv6(const u_char *packet, int offset, int packet_length) {
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(packet + offset);
    
    uint8_t type = icmp6_header->icmp6_type;
    uint8_t code = icmp6_header->icmp6_code;
    uint16_t checksum = ntohs(icmp6_header->icmp6_cksum);
    
    // Map ICMPv6 type to human-readable name
    const char *type_name;
    switch (type) {
        case 1: type_name = "Destination Unreachable"; break;
        case 2: type_name = "Packet Too Big"; break;
        case 3: type_name = "Time Exceeded"; break;
        case 4: type_name = "Parameter Problem"; break;
        case 128: type_name = "Echo Request (Ping)"; break;
        case 129: type_name = "Echo Reply (Pong)"; break;
        case 133: type_name = "Router Solicitation"; break;
        case 134: type_name = "Router Advertisement"; break;
        case 135: type_name = "Neighbor Solicitation"; break;
        case 136: type_name = "Neighbor Advertisement"; break;
        case 137: type_name = "Redirect Message"; break;
        default: type_name = "Unknown"; break;
    }
    
    printf("L4 (ICMPv6): Type: %d (%s) | Code: %d | Checksum: 0x%04X\n",
           type, type_name, code, checksum);
    
    // Decode specific ICMPv6 message details (L7 information)
    int icmp6_header_len = sizeof(struct icmp6_hdr);
    int payload_offset = offset + icmp6_header_len;
    int payload_len = packet_length - payload_offset;
    
    if (payload_len > 0) {
        printf("L7 (ICMPv6 Payload): ");
        
        switch (type) {
            case 128: // Echo Request
            case 129: // Echo Reply
                {
                    // Echo has identifier and sequence number
                    uint16_t id = ntohs(icmp6_header->icmp6_id);
                    uint16_t seq = ntohs(icmp6_header->icmp6_seq);
                    printf("Echo ID: %d | Sequence: %d | Data: %d bytes\n", id, seq, payload_len - 4);
                    if (payload_len > 4) {
                        printf("    Echo Data (first %d bytes):\n", payload_len - 4 > 32 ? 32 : payload_len - 4);
                        print_hex_ascii(packet + payload_offset, payload_len - 4 > 32 ? 32 : payload_len - 4);
                    }
                }
                break;
                
            case 135: // Neighbor Solicitation
                printf("Neighbor Discovery - Solicitation\n");
                if (payload_len >= 20) {
                    // Target address is at offset 4-19 (16 bytes)
                    char target_ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, packet + payload_offset + 4, target_ip, INET6_ADDRSTRLEN);
                    printf("    Target Address: %s\n", target_ip);
                }
                break;
                
            case 136: // Neighbor Advertisement
                printf("Neighbor Discovery - Advertisement\n");
                if (payload_len >= 20) {
                    char target_ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, packet + payload_offset + 4, target_ip, INET6_ADDRSTRLEN);
                    printf("    Target Address: %s\n", target_ip);
                }
                break;
                
            case 134: // Router Advertisement
                printf("Router Discovery - Advertisement\n");
                printf("    Message details: %d bytes\n", payload_len);
                break;
                
            case 133: // Router Solicitation
                printf("Router Discovery - Solicitation\n");
                printf("    Message details: %d bytes\n", payload_len);
                break;
                
            default:
                printf("Payload: %d bytes\n", payload_len);
                if (payload_len > 0) {
                    printf("    Data (first %d bytes):\n", payload_len > 32 ? 32 : payload_len);
                    print_hex_ascii(packet + payload_offset, payload_len > 32 ? 32 : payload_len);
                }
                break;
        }
        
        // Print first 64 bytes of entire packet starting from Ethernet header (byte 0)
        // packet currently points to IPv6 header, need to go back by Ethernet header size
        printf("    Data (first 64 bytes from packet start):\n");
        const u_char *packet_start = packet - sizeof(struct ether_header);
        int total_packet_length = packet_length + sizeof(struct ether_header);
        int bytes_to_print = total_packet_length > 64 ? 64 : total_packet_length;
        print_hex_ascii(packet_start, bytes_to_print);
    }
}

void decode_payload(const u_char *packet, int offset, int total_len, int port, int packet_length) {
    if (total_len <= 0) return;
    
    const char *protocol;
    if (port == 80) protocol = "HTTP";
    else if (port == 443) protocol = "HTTPS/TLS";
    else if (port == 53) protocol = "DNS";
    else protocol = "Unknown";
    
    printf("L7 (Payload): Identified as %s on port %d - %d bytes\n",
           protocol, port, total_len);
    
    // Print first 64 bytes from the START of the packet (including all headers)
    int bytes_to_print = packet_length > 64 ? 64 : packet_length;
    printf("    Data (first %d bytes from packet start):\n", bytes_to_print);
    print_hex_ascii(packet, bytes_to_print);
}

//#########LLM GENERATED CODE ENDS#########