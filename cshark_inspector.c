//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

void inspect_session(void) {
    if (!current_session || current_session->packet_count == 0) {
        printf("\n[C-Shark] No packets captured in the last session.\n");
        printf("Please run a sniffing session first.\n");
        return;
    }
    
    printf("\n[C-Shark] Last Session Summary\n");
    printf("=====================================\n");
    printf("Total packets captured: %d\n", current_session->packet_count);
    
    const char *filter_names[] = {
        "None", "HTTP", "HTTPS", "DNS", "ARP", "TCP", "UDP"
    };
    printf("Filter applied: %s\n\n", filter_names[current_session->filter_type]);
    
    // Display packet list with summary
    printf("Packet List:\n");
    printf("ID\tTimestamp\t\tLength\tProtocol Info\n");
    printf("----------------------------------------------------------------\n");
    
    stored_packet_t *current = current_session->head;
    while (current) {
        // Get basic protocol info for summary
        struct ether_header *eth = (struct ether_header *)current->data;
        uint16_t ether_type = ntohs(eth->ether_type);
        
        char proto_info[128] = "";
        
        if (ether_type == ETHERTYPE_IP) {
            struct ip *ip_hdr = (struct ip *)(current->data + sizeof(struct ether_header));
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
            
            const char *proto = "";
            switch (ip_hdr->ip_p) {
                case IPPROTO_TCP: proto = "TCP"; break;
                case IPPROTO_UDP: proto = "UDP"; break;
                case IPPROTO_ICMP: proto = "ICMP"; break;
                default: proto = "Other"; break;
            }
            
            snprintf(proto_info, sizeof(proto_info), "IPv4/%s %s->%s", 
                     proto, src_ip, dst_ip);
        } else if (ether_type == ETHERTYPE_IPV6) {
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(current->data + sizeof(struct ether_header));
            char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
            
            const char *proto = "";
            switch (ip6_hdr->ip6_nxt) {
                case IPPROTO_TCP: proto = "TCP"; break;
                case IPPROTO_UDP: proto = "UDP"; break;
                case IPPROTO_ICMPV6: proto = "ICMPv6"; break;
                default: proto = "Other"; break;
            }
            
            // Truncate IPv6 addresses for display
            char src_short[32], dst_short[32];
            strncpy(src_short, src_ip, 20);
            strncpy(dst_short, dst_ip, 20);
            src_short[20] = dst_short[20] = '\0';
            strcat(src_short, "...");
            strcat(dst_short, "...");
            
            snprintf(proto_info, sizeof(proto_info), "IPv6/%s %s->%s", 
                     proto, src_short, dst_short);
        } else if (ether_type == ETHERTYPE_ARP) {
            snprintf(proto_info, sizeof(proto_info), "ARP");
        } else {
            snprintf(proto_info, sizeof(proto_info), "Unknown (0x%04X)", ether_type);
        }
        
        printf("%d\t%ld.%06d\t%d\t%s\n", 
               current->id, 
               current->timestamp.tv_sec,
               (int)current->timestamp.tv_usec, 
               current->captured_length,
               proto_info);
        
        current = current->next;
    }
    
    printf("\nEnter Packet ID to inspect in detail (or 0 to return to menu): ");
    int packet_id;
    if (scanf("%d", &packet_id) == EOF) {
        extern void cleanup_and_exit(void);
        cleanup_and_exit();
    }
    int ch = getchar();
    if (ch == EOF) {
        extern void cleanup_and_exit(void);
        cleanup_and_exit();
    }
    
    if (packet_id == 0) {
        return;
    }
    
    // Find the packet
    current = current_session->head;
    stored_packet_t *found = NULL;
    while (current) {
        if (current->id == packet_id) {
            found = current;
            break;
        }
        current = current->next;
    }
    
    if (!found) {
        printf("\n[C-Shark] Packet #%d not found in session.\n", packet_id);
        return;
    }
    
    // Display detailed packet info
    show_detailed_packet(found);
    
    // Ask if user wants to inspect another packet
    printf("\nPress Enter to continue...");
    int ch2 = getchar();
    if (ch2 == EOF) {
        extern void cleanup_and_exit(void);
        cleanup_and_exit();
    }
}

void show_detailed_packet(stored_packet_t *pkt) {
    printf("\n");
    printf("================================================================================\n");
    printf("                     C-SHARK DETAILED PACKET ANALYSIS                          \n");
    printf("================================================================================\n");
    printf("\n");
    
    printf("🔍 PACKET SUMMARY\n");
    printf("\n");
    printf("Packet ID:        #%d\n", pkt->id);
    printf("Timestamp:        %ld.%06d\n", pkt->timestamp.tv_sec, (int)pkt->timestamp.tv_usec);
    printf("Frame Length:     %d bytes\n", pkt->length);
    printf("Captured:         %d bytes\n", pkt->captured_length);
    printf("\n");
    
    // Layer 2 - Ethernet
    printf("📡 ETHERNET II FRAME (Layer 2)\n");
    printf("\n");
    struct ether_header *eth = (struct ether_header *)pkt->data;
    
    printf("Destination MAC:  %02X:%02X:%02X:%02X:%02X:%02X (Bytes 0-5)\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    
    printf("Source MAC:       %02X:%02X:%02X:%02X:%02X:%02X (Bytes 6-11)\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    
    uint16_t ether_type = ntohs(eth->ether_type);
    printf("EtherType:        0x%04X (%s) (Bytes 12-13)\n", ether_type, get_ethertype_name(ether_type));
    printf("  └─ Hex: %02X %02X\n", pkt->data[12], pkt->data[13]);
    printf("\n");
    
    // Layer 3
    if (ether_type == ETHERTYPE_IP) {
        printf("🌐 IPv4 HEADER (Layer 3)\n");
        printf("\n");
        struct ip *ip_hdr = (struct ip *)(pkt->data + sizeof(struct ether_header));
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        // Byte 14 (Version + IHL)
        printf("Version:          %d (4-bit field in byte 14)\n", ip_hdr->ip_v);
        printf("  └─ Hex: %02X (upper 4 bits = %d)\n", pkt->data[14], ip_hdr->ip_v);
        
        printf("Header Length:    %d bytes (5 * 4) (4-bit field in byte 14)\n", ip_hdr_len);
        printf("  └─ Hex: %02X (lower 4 bits = %d)\n", pkt->data[14], ip_hdr->ip_hl);
        
        // Byte 15 (Type of Service / DSCP + ECN)
        printf("Type of Service:  0x%02X (Byte 15)\n", ip_hdr->ip_tos);
        printf("  └─ DSCP: %d, ECN: %d\n", (ip_hdr->ip_tos >> 2) & 0x3F, ip_hdr->ip_tos & 0x03);
        printf("  └─ Hex: %02X\n", pkt->data[15]);
        
        // Bytes 16-17 (Total Length)
        uint16_t total_len = ntohs(ip_hdr->ip_len);
        printf("Total Length:     %d bytes (Bytes 16-17)\n", total_len);
        printf("  └─ Hex: %02X %02X\n", pkt->data[16], pkt->data[17]);
        
        // Bytes 18-19 (Identification)
        printf("Identification:   0x%04X (%d) (Bytes 18-19)\n", ntohs(ip_hdr->ip_id), ntohs(ip_hdr->ip_id));
        printf("  └─ Hex: %02X %02X\n", pkt->data[18], pkt->data[19]);
        
        // Bytes 20-21 (Flags + Fragment Offset)
        int flags = ntohs(ip_hdr->ip_off);
        printf("Flags:            0x%04X (Byte 20-21)\n", flags);
        printf("  └─ Reserved: %d, Don't Fragment: %d, More Fragments: %d\n",
               (flags >> 15) & 0x01, (flags >> 14) & 0x01, (flags >> 13) & 0x01);
        printf("  └─ Hex: %02X %02X\n", pkt->data[20], pkt->data[21]);
        
        printf("Fragment Offset:  %d bytes\n", (flags & IP_OFFMASK) * 8);
        
        // Byte 22 (Time to Live)
        printf("Time to Live:     %d (Byte 22)\n", ip_hdr->ip_ttl);
        printf("  └─ Hex: %02X\n", pkt->data[22]);
        
        // Byte 23 (Protocol)
        printf("Protocol:         %d", ip_hdr->ip_p);
        switch (ip_hdr->ip_p) {
            case IPPROTO_TCP: printf(" (TCP)"); break;
            case IPPROTO_UDP: printf(" (UDP)"); break;
            case IPPROTO_ICMP: printf(" (ICMP)"); break;
        }
        printf(" (Byte 23)\n");
        printf("  └─ Hex: %02X\n", pkt->data[23]);
        
        // Bytes 24-25 (Header Checksum)
        printf("Header Checksum:  0x%04X (Bytes 24-25)\n", ntohs(ip_hdr->ip_sum));
        printf("  └─ Hex: %02X %02X\n", pkt->data[24], pkt->data[25]);
        
        // Bytes 26-29 (Source IP)
        printf("Source IP:        %s (Bytes 26-29)\n", src_ip);
        printf("  └─ Hex: %02X %02X %02X %02X\n", pkt->data[26], pkt->data[27], pkt->data[28], pkt->data[29]);
        
        // Bytes 30-33 (Destination IP)
        printf("Destination IP:   %s (Bytes 30-33)\n", dst_ip);
        printf("  └─ Hex: %02X %02X %02X %02X\n", pkt->data[30], pkt->data[31], pkt->data[32], pkt->data[33]);
        printf("\n");
        
        // Layer 4
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            printf("🔧 TCP HEADER (Layer 4)\n");
            printf("\n");
            struct tcphdr *tcp = (struct tcphdr *)(pkt->data + sizeof(struct ether_header) + ip_hdr_len);
            
            // macOS uses th_off, Linux uses doff
            #ifdef __APPLE__
            int tcp_hdr_len = tcp->th_off * 4;
            #else
            int tcp_hdr_len = tcp->doff * 4;
            #endif
            
            int tcp_offset = sizeof(struct ether_header) + ip_hdr_len;
            
            // Bytes 34-35 (Source Port) - macOS uses th_sport, Linux uses source
            #ifdef __APPLE__
            printf("Source Port:      %d%s (Bytes 34-35)\n", ntohs(tcp->th_sport), get_port_name(ntohs(tcp->th_sport)));
            #else
            printf("Source Port:      %d%s (Bytes 34-35)\n", ntohs(tcp->source), get_port_name(ntohs(tcp->source)));
            #endif
            printf("  └─ Hex: %02X %02X\n", pkt->data[tcp_offset], pkt->data[tcp_offset+1]);
            
            // Bytes 36-37 (Destination Port) - macOS uses th_dport, Linux uses dest
            #ifdef __APPLE__
            printf("Destination Port: %d%s (Bytes 36-37)\n", ntohs(tcp->th_dport), get_port_name(ntohs(tcp->th_dport)));
            #else
            printf("Destination Port: %d%s (Bytes 36-37)\n", ntohs(tcp->dest), get_port_name(ntohs(tcp->dest)));
            #endif
            printf("  └─ Hex: %02X %02X\n", pkt->data[tcp_offset+2], pkt->data[tcp_offset+3]);
            
            // Bytes 38-41 (Sequence Number) - macOS uses th_seq, Linux uses seq
            #ifdef __APPLE__
            printf("Sequence Number:  %u (Bytes 38-41)\n", ntohl(tcp->th_seq));
            #else
            printf("Sequence Number:  %u (Bytes 38-41)\n", ntohl(tcp->seq));
            #endif
            printf("  └─ Hex: %02X %02X %02X %02X\n", 
                   pkt->data[tcp_offset+4], pkt->data[tcp_offset+5],
                   pkt->data[tcp_offset+6], pkt->data[tcp_offset+7]);
            
            // Bytes 42-45 (Acknowledgment Number) - macOS uses th_ack, Linux uses ack_seq
            #ifdef __APPLE__
            printf("Ack Number:       %u (Bytes 42-45)\n", ntohl(tcp->th_ack));
            #else
            printf("Ack Number:       %u (Bytes 42-45)\n", ntohl(tcp->ack_seq));
            #endif
            printf("  └─ Hex: %02X %02X %02X %02X\n",
                   pkt->data[tcp_offset+8], pkt->data[tcp_offset+9],
                   pkt->data[tcp_offset+10], pkt->data[tcp_offset+11]);
            
            // Byte 46 (Data Offset + Reserved + NS flag)
            printf("Header Length:    %d bytes (8 * 4) (Upper 4 bits of byte 46)\n", tcp_hdr_len);
            #ifdef __APPLE__
            printf("  └─ Hex: %02X (upper 4 bits = %d)\n", pkt->data[tcp_offset+12], tcp->th_off);
            #else
            printf("  └─ Hex: %02X (upper 4 bits = %d)\n", pkt->data[tcp_offset+12], tcp->doff);
            #endif
            
            // Byte 47 (Flags) - macOS uses th_flags with TH_* constants, Linux uses bit fields
            printf("Flags:            0x%02X (Byte 47)\n", pkt->data[tcp_offset+13]);
            #ifdef __APPLE__
            printf("  └─ URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
                   (tcp->th_flags & TH_URG) ? 1 : 0,
                   (tcp->th_flags & TH_ACK) ? 1 : 0,
                   (tcp->th_flags & TH_PUSH) ? 1 : 0,
                   (tcp->th_flags & TH_RST) ? 1 : 0,
                   (tcp->th_flags & TH_SYN) ? 1 : 0,
                   (tcp->th_flags & TH_FIN) ? 1 : 0);
            #else
            printf("  └─ URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
                   tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
            #endif
            printf("  └─ Hex: %02X\n", pkt->data[tcp_offset+13]);
            
            // Bytes 48-49 (Window Size) - macOS uses th_win, Linux uses window
            #ifdef __APPLE__
            printf("Window Size:      %d (Bytes 48-49)\n", ntohs(tcp->th_win));
            #else
            printf("Window Size:      %d (Bytes 48-49)\n", ntohs(tcp->window));
            #endif
            printf("  └─ Hex: %02X %02X\n", pkt->data[tcp_offset+14], pkt->data[tcp_offset+15]);
            
            // Bytes 50-51 (Checksum) - macOS uses th_sum, Linux uses check
            #ifdef __APPLE__
            printf("Checksum:         0x%04X (Bytes 50-51)\n", ntohs(tcp->th_sum));
            #else
            printf("Checksum:         0x%04X (Bytes 50-51)\n", ntohs(tcp->check));
            #endif
            printf("  └─ Hex: %02X %02X\n", pkt->data[tcp_offset+16], pkt->data[tcp_offset+17]);
            
            // Bytes 52-53 (Urgent Pointer) - macOS uses th_urp, Linux uses urg_ptr
            #ifdef __APPLE__
            printf("Urgent Pointer:   %d (Bytes 52-53)\n", ntohs(tcp->th_urp));
            #else
            printf("Urgent Pointer:   %d (Bytes 52-53)\n", ntohs(tcp->urg_ptr));
            #endif
            printf("  └─ Hex: %02X %02X\n", pkt->data[tcp_offset+18], pkt->data[tcp_offset+19]);
            
            // TCP Options (if any)
            if (tcp_hdr_len > 20) {
                printf("TCP Options:      %d bytes (Bytes 54-%d)\n", tcp_hdr_len - 20, tcp_offset + tcp_hdr_len - 1);
                printf("  └─ Hex: ");
                for (int i = 20; i < tcp_hdr_len && i < 32; i++) {
                    printf("%02X ", pkt->data[tcp_offset+i]);
                }
                if (tcp_hdr_len > 32) printf("...");
                printf("\n");
            }
            printf("\n");
            
            // Payload
            int payload_offset = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;
            int payload_len = pkt->captured_length - payload_offset;
            if (payload_len > 0) {
                printf("📦 APPLICATION DATA (Layer 5-7)\n");
                printf("\n");
                printf("Payload Length:   %d bytes (Bytes %d-%d)\n", 
                       payload_len, payload_offset, pkt->captured_length - 1);
                
                #ifdef __APPLE__
                int port = ntohs(tcp->th_dport);
                #else
                int port = ntohs(tcp->dest);
                #endif
                printf("Protocol:         ");
                if (port == 80) printf("HTTP");
                else if (port == 443) printf("HTTPS/TLS");
                else if (port == 22) printf("SSH");
                else if (port == 8080) printf("HTTP-Alt/Proxy");
                else printf("Unknown/Custom");
                printf(" (Port %d)\n", port);
                printf("\n");
                
                printf("First 64 bytes of packet:\n");
                int packet_len = pkt->length;
                print_hex_ascii(pkt->data, packet_len > 64 ? 64 : packet_len);
                
                if (packet_len > 64) {
                    printf("\n... and %d more bytes\n", packet_len - 64);
                }
                printf("\n");
            }
            
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            printf("=== LAYER 4: UDP HEADER ===\n");
            struct udphdr *udp = (struct udphdr *)(pkt->data + sizeof(struct ether_header) + ip_hdr_len);
            
            printf("Raw UDP Header (8 bytes):\n");
            print_hex_dump(pkt->data + sizeof(struct ether_header) + ip_hdr_len, 8, 8);
            printf("\n");
            
            printf("Decoded:\n");
            #ifdef __APPLE__
            printf("  Source Port:      %d%s\n", ntohs(udp->uh_sport), get_port_name(ntohs(udp->uh_sport)));
            printf("  Destination Port: %d%s\n", ntohs(udp->uh_dport), get_port_name(ntohs(udp->uh_dport)));
            printf("  Length:           %d bytes\n", ntohs(udp->uh_ulen));
            printf("  Checksum:         0x%04X\n\n", ntohs(udp->uh_sum));
            #else
            printf("  Source Port:      %d%s\n", ntohs(udp->source), get_port_name(ntohs(udp->source)));
            printf("  Destination Port: %d%s\n", ntohs(udp->dest), get_port_name(ntohs(udp->dest)));
            printf("  Length:           %d bytes\n", ntohs(udp->len));
            printf("  Checksum:         0x%04X\n\n", ntohs(udp->check));
            #endif
            
            // Payload
            #ifdef __APPLE__
            int payload_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
            #else
            int payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            #endif
            if (payload_len > 0) {
                printf("=== LAYER 7: APPLICATION DATA ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("Protocol: ");
                #ifdef __APPLE__
                int port = ntohs(udp->uh_dport);
                #else
                int port = ntohs(udp->dest);
                #endif
                if (port == 53) printf("DNS");
                else printf("Unknown");
                printf(" (based on port %d)\n\n", port);
                
                printf("First 64 bytes of packet:\n");
                int packet_len = pkt->length;
                print_hex_ascii(pkt->data, packet_len > 64 ? 64 : packet_len);
                
                if (packet_len > 64) {
                    printf("\n... and %d more bytes\n", packet_len - 64);
                }
            }
        }
        
    } else if (ether_type == ETHERTYPE_IPV6) {
        printf("=== LAYER 3: IPv6 HEADER ===\n");
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt->data + sizeof(struct ether_header));
        
        printf("Raw IPv6 Header (40 bytes):\n");
        print_hex_dump(pkt->data + sizeof(struct ether_header), 40, 40);
        printf("\n");
        
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        
        printf("Decoded:\n");
        printf("  Version:         %d\n", (ip6->ip6_flow >> 28) & 0xF);
        printf("  Traffic Class:   %d\n", (ip6->ip6_flow >> 20) & 0xFF);
        printf("  Flow Label:      0x%05X\n", ntohl(ip6->ip6_flow) & 0xFFFFF);
        printf("  Payload Length:  %d bytes\n", ntohs(ip6->ip6_plen));
        printf("  Next Header:     %d", ip6->ip6_nxt);
        switch (ip6->ip6_nxt) {
            case IPPROTO_TCP: printf(" (TCP)"); break;
            case IPPROTO_UDP: printf(" (UDP)"); break;
            case IPPROTO_ICMPV6: printf(" (ICMPv6)"); break;
        }
        printf("\n");
        printf("  Hop Limit:       %d\n", ip6->ip6_hlim);
        printf("  Source IP:       %s\n", src_ip);
        printf("  Destination IP:  %s\n\n", dst_ip);
        
        // Layer 4 for IPv6
        if (ip6->ip6_nxt == IPPROTO_TCP) {
            printf("=== LAYER 4: TCP HEADER ===\n");
            struct tcphdr *tcp = (struct tcphdr *)(pkt->data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            
            #ifdef __APPLE__
            int tcp_hdr_len = tcp->th_off * 4;
            #else
            int tcp_hdr_len = tcp->doff * 4;
            #endif
            
            printf("Raw TCP Header (%d bytes):\n", tcp_hdr_len);
            print_hex_dump(pkt->data + sizeof(struct ether_header) + sizeof(struct ip6_hdr), tcp_hdr_len, tcp_hdr_len);
            printf("\n");
            
            printf("Decoded:\n");
            #ifdef __APPLE__
            printf("  Source Port:      %d%s\n", ntohs(tcp->th_sport), get_port_name(ntohs(tcp->th_sport)));
            printf("  Destination Port: %d%s\n", ntohs(tcp->th_dport), get_port_name(ntohs(tcp->th_dport)));
            printf("  Sequence Number:  %u\n", ntohl(tcp->th_seq));
            printf("  Ack Number:       %u\n", ntohl(tcp->th_ack));
            #else
            printf("  Source Port:      %d%s\n", ntohs(tcp->source), get_port_name(ntohs(tcp->source)));
            printf("  Destination Port: %d%s\n", ntohs(tcp->dest), get_port_name(ntohs(tcp->dest)));
            printf("  Sequence Number:  %u\n", ntohl(tcp->seq));
            printf("  Ack Number:       %u\n", ntohl(tcp->ack_seq));
            #endif
            
            printf("  Header Length:    %d bytes\n", tcp_hdr_len);
            printf("  Flags:            ");
            
            #ifdef __APPLE__
            if (tcp->th_flags & TH_FIN) printf("FIN ");
            if (tcp->th_flags & TH_SYN) printf("SYN ");
            if (tcp->th_flags & TH_RST) printf("RST ");
            if (tcp->th_flags & TH_PUSH) printf("PSH ");
            if (tcp->th_flags & TH_ACK) printf("ACK ");
            if (tcp->th_flags & TH_URG) printf("URG ");
            #else
            if (tcp->fin) printf("FIN ");
            if (tcp->syn) printf("SYN ");
            if (tcp->rst) printf("RST ");
            if (tcp->psh) printf("PSH ");
            if (tcp->ack) printf("ACK ");
            if (tcp->urg) printf("URG ");
            #endif
            
            printf("\n");
            
            #ifdef __APPLE__
            printf("  Window Size:      %d\n", ntohs(tcp->th_win));
            printf("  Checksum:         0x%04X\n", ntohs(tcp->th_sum));
            printf("  Urgent Pointer:   %d\n\n", ntohs(tcp->th_urp));
            #else
            printf("  Window Size:      %d\n", ntohs(tcp->window));
            printf("  Checksum:         0x%04X\n", ntohs(tcp->check));
            printf("  Urgent Pointer:   %d\n\n", ntohs(tcp->urg_ptr));
            #endif
            
            // Payload
            int payload_offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + tcp_hdr_len;
            int payload_len = pkt->captured_length - payload_offset;
            if (payload_len > 0) {
                printf("=== LAYER 7: APPLICATION DATA ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("Protocol: ");
                
                #ifdef __APPLE__
                int port = ntohs(tcp->th_dport);
                #else
                int port = ntohs(tcp->dest);
                #endif
                
                if (port == 80) printf("HTTP");
                else if (port == 443) printf("HTTPS/TLS");
                else if (port == 22) printf("SSH");
                else printf("Unknown");
                printf(" (based on port %d)\n\n", port);
                
                printf("First 64 bytes of packet:\n");
                int packet_len = pkt->length;
                print_hex_ascii(pkt->data, packet_len > 64 ? 64 : packet_len);
                
                if (packet_len > 64) {
                    printf("\n... and %d more bytes\n", packet_len - 64);
                }
            }
            
        } else if (ip6->ip6_nxt == IPPROTO_UDP) {
            printf("=== LAYER 4: UDP HEADER ===\n");
            struct udphdr *udp = (struct udphdr *)(pkt->data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            
            printf("Raw UDP Header (8 bytes):\n");
            print_hex_dump(pkt->data + sizeof(struct ether_header) + sizeof(struct ip6_hdr), 8, 8);
            printf("\n");
            
            printf("Decoded:\n");
            #ifdef __APPLE__
            printf("  Source Port:      %d%s\n", ntohs(udp->uh_sport), get_port_name(ntohs(udp->uh_sport)));
            printf("  Destination Port: %d%s\n", ntohs(udp->uh_dport), get_port_name(ntohs(udp->uh_dport)));
            printf("  Length:           %d bytes\n", ntohs(udp->uh_ulen));
            printf("  Checksum:         0x%04X\n\n", ntohs(udp->uh_sum));
            #else
            printf("  Source Port:      %d%s\n", ntohs(udp->source), get_port_name(ntohs(udp->source)));
            printf("  Destination Port: %d%s\n", ntohs(udp->dest), get_port_name(ntohs(udp->dest)));
            printf("  Length:           %d bytes\n", ntohs(udp->len));
            printf("  Checksum:         0x%04X\n\n", ntohs(udp->check));
            #endif
            
            // Payload
            #ifdef __APPLE__
            int payload_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
            #else
            int payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            #endif
            if (payload_len > 0) {
                printf("=== LAYER 7: APPLICATION DATA ===\n");
                printf("Payload Length: %d bytes\n", payload_len);
                printf("Protocol: ");
                #ifdef __APPLE__
                int port = ntohs(udp->uh_dport);
                #else
                int port = ntohs(udp->dest);
                #endif
                if (port == 53) printf("DNS");
                else printf("Unknown");
                printf(" (based on port %d)\n\n", port);
                
                printf("First 64 bytes of packet:\n");
                int packet_len = pkt->length;
                print_hex_ascii(pkt->data, packet_len > 64 ? 64 : packet_len);
                
                if (packet_len > 64) {
                    printf("\n... and %d more bytes\n", packet_len - 64);
                }
            }
        }
        
    } else if (ether_type == ETHERTYPE_ARP) {
        printf("=== LAYER 3: ARP PACKET ===\n");
        struct arphdr *arp = (struct arphdr *)(pkt->data + sizeof(struct ether_header));
        
        printf("Raw ARP Packet (28 bytes for Ethernet/IPv4):\n");
        print_hex_dump(pkt->data + sizeof(struct ether_header), 28, 28);
        printf("\n");
        
        printf("Decoded ARP Header:\n");
        printf("  Hardware Type:   %d", ntohs(arp->ar_hrd));
        if (ntohs(arp->ar_hrd) == ARPHRD_ETHER) printf(" (Ethernet)");
        printf("\n");
        printf("  Protocol Type:   0x%04X", ntohs(arp->ar_pro));
        if (ntohs(arp->ar_pro) == ETHERTYPE_IP) printf(" (IPv4)");
        printf("\n");
        printf("  Hardware Length: %d\n", arp->ar_hln);
        printf("  Protocol Length: %d\n", arp->ar_pln);
        printf("  Operation:       %d", ntohs(arp->ar_op));
        switch (ntohs(arp->ar_op)) {
            case ARPOP_REQUEST: printf(" (Request)"); break;
            case ARPOP_REPLY: printf(" (Reply)"); break;
        }
        printf("\n");
        
        if (ntohs(arp->ar_hrd) == ARPHRD_ETHER && ntohs(arp->ar_pro) == ETHERTYPE_IP) {
            const u_char *arp_data = pkt->data + sizeof(struct ether_header) + sizeof(struct arphdr);
            
            u_char sender_mac[6], target_mac[6];
            struct in_addr sender_ip, target_ip;
            
            memcpy(sender_mac, arp_data, 6);
            memcpy(&sender_ip, arp_data + 6, 4);
            memcpy(target_mac, arp_data + 10, 6);
            memcpy(&target_ip, arp_data + 14, 4);
            
            char sender_ip_str[INET_ADDRSTRLEN], target_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_ip, sender_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &target_ip, target_ip_str, INET_ADDRSTRLEN);
            
            printf("\nARP Addresses:\n");
            printf("  Sender MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
                   sender_mac[0], sender_mac[1], sender_mac[2],
                   sender_mac[3], sender_mac[4], sender_mac[5]);
            printf("  Sender IP:       %s\n", sender_ip_str);
            printf("  Target MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
                   target_mac[0], target_mac[1], target_mac[2],
                   target_mac[3], target_mac[4], target_mac[5]);
            printf("  Target IP:       %s\n", target_ip_str);
        }
    }
    
    printf("📋 COMPLETE FRAME HEX DUMP\n");
    printf("\n");
    printf("Complete packet frame (%d bytes):\n\n", pkt->captured_length);
    printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
    printf("     -------------------------------------------------------      ----------------\n");
    print_hex_ascii(pkt->data, pkt->captured_length);
    printf("\n");
    
    printf("================================================================================\n");
    printf("                        END OF PACKET ANALYSIS                                  \n");
    printf("================================================================================\n");
}
//#########LLM GENERATED CODE ENDS#########