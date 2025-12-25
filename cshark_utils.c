//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

const char* get_port_name(int port) {
    static char port_str[32];
    
    switch (port) {
        case 80: return " (HTTP)";
        case 443: return " (HTTPS)";
        case 53: return " (DNS)";
        case 22: return " (SSH)";
        case 21: return " (FTP)";
        case 25: return " (SMTP)";
        case 110: return " (POP3)";
        case 143: return " (IMAP)";
        case 3306: return " (MySQL)";
        case 3389: return " (RDP)";
        case 8080: return " (HTTP-ALT)";
        case 8443: return " (HTTPS-ALT)";
        default: 
            port_str[0] = '\0';
            return port_str;
    }
}

const char* get_ethertype_name(uint16_t type) {
    switch (type) {
        case ETHERTYPE_IP: return "IPv4";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_REVARP: return "RARP";
        case 0x8100: return "VLAN";
        case 0x88A8: return "VLAN Double Tag";
        default: return "Unknown";
    }
}

void print_hex_dump(const u_char *data, int len, int max_len) {
    int display_len = (len > max_len) ? max_len : len;
    int i, j;
    
    for (i = 0; i < display_len; i += 16) {
        // Print offset
        printf("    %04X: ", i);
        
        // Print hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < display_len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" ");
        
        // Print ASCII
        for (j = 0; j < 16; j++) {
            if (i + j < display_len) {
                u_char c = data[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("\n");
    }
    
    if (len > max_len) {
        printf("    ... (%d more bytes)\n", len - max_len);
    }
}

int should_capture_packet(const u_char *packet, int len, int filter_type) {
    // This function is for future use if you want to implement
    // more sophisticated filtering beyond what pcap filters provide
    // For now, return 1 (capture all) as filtering is done by pcap
    return 1;
}
//#########LLM GENERATED CODE ENDS#########