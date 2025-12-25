//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

pcap_t *global_pcap_handle = NULL;
void sniff_all(const char *device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Initialize new session
    current_session = (session_t *)malloc(sizeof(session_t));
    current_session->head = NULL;
    current_session->tail = NULL;
    current_session->packet_count = 0;
    current_session->filter_type = 0;
    
    // Reset counters
    packet_counter = 0;
    keep_sniffing = 1;
    
    // Open device for sniffing
    global_pcap_handle = pcap_open_live(device_name, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (global_pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
        return;
    }
    
    // Set to non-blocking mode so pcap_dispatch returns immediately
    if (pcap_setnonblock(global_pcap_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
        pcap_close(global_pcap_handle);
        return;
    }

    printf("\n[C-Shark] Starting packet capture on %s (Press Ctrl+C to stop, Ctrl+D to exit)...\n\n", device_name);

    // Set terminal to raw mode for immediate input detection
    struct termios old_tio, new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);

    // Process packets in batches and check stdin between batches
    while (keep_sniffing) {
        // Dispatch a batch of packets (non-blocking)
        pcap_dispatch(global_pcap_handle, 10, packet_handler, (u_char *)global_pcap_handle);
        
        // Check stdin for Ctrl+D using non-blocking select
        fd_set readfds;
        struct timeval timeout = {0, 0}; // Non-blocking
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        if (select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout) > 0) {
            char ch;
            ssize_t result = read(STDIN_FILENO, &ch, 1);
            if (result > 0 && ch == 4) {
                // EOT detected (Ctrl+D in raw mode = ASCII 4)
                tcsetattr(STDIN_FILENO, TCSANOW, &old_tio); // Restore terminal mode
                printf("\n[C-Shark] Ctrl+D detected, exiting...\n");
                pcap_breakloop(global_pcap_handle);
                pcap_close(global_pcap_handle);
                global_pcap_handle = NULL;
                extern void cleanup_and_exit(void);
                cleanup_and_exit();
            }
        }
        
        // Small delay to prevent busy-waiting
        usleep(1000); // 1ms
    }

    // Restore terminal mode
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    
    pcap_close(global_pcap_handle);
    global_pcap_handle = NULL;
    printf("\n[C-Shark] Captured %d packets in this session.\n", packet_counter);
}

void sniff_filtered(const char *device_name, int filter_type) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[256] = "";
    
    // Initialize new session
    current_session = (session_t *)malloc(sizeof(session_t));
    current_session->head = NULL;
    current_session->tail = NULL;
    current_session->packet_count = 0;
    current_session->filter_type = filter_type;
    
    // Reset counters
    packet_counter = 0;
    keep_sniffing = 1;
    
    // Build filter expression
    switch (filter_type) {
        case 1: // HTTP
            strcpy(filter_exp, "tcp port 80");
            break;
        case 2: // HTTPS
            strcpy(filter_exp, "tcp port 443");
            break;
        case 3: // DNS
            strcpy(filter_exp, "udp port 53");
            break;
        case 4: // ARP
            strcpy(filter_exp, "arp");
            break;
        case 5: // TCP
            strcpy(filter_exp, "tcp");
            break;
        case 6: // UDP
            strcpy(filter_exp, "udp");
            break;
    }
    
    // Open device for sniffing
    global_pcap_handle = pcap_open_live(device_name, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    handle = global_pcap_handle;
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
        return;
    }
    
    // Set to non-blocking mode so pcap_dispatch returns immediately
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        return;
    }
    
    // Compile and apply filter
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    
    printf("\n[C-Shark] Starting filtered capture (%s) on %s (Press Ctrl+C to stop, Ctrl+D to exit)...\n\n", 
           filter_exp, device_name);
    
    // Set terminal to raw mode for immediate input detection
    struct termios old_tio, new_tio;
    tcgetattr(STDIN_FILENO, &old_tio);
    new_tio = old_tio;
    new_tio.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
    
    // Process packets in batches and check stdin between batches
    while (keep_sniffing) {
        // Dispatch a batch of packets (non-blocking)
        pcap_dispatch(handle, 10, packet_handler, (u_char *)handle);
        
        // Check stdin for Ctrl+D using non-blocking select
        fd_set readfds;
        struct timeval timeout = {0, 0}; // Non-blocking
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        if (select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout) > 0) {
            char ch;
            ssize_t result = read(STDIN_FILENO, &ch, 1);
            if (result > 0 && ch == 4) {
                // EOT detected (Ctrl+D in raw mode = ASCII 4)
                tcsetattr(STDIN_FILENO, TCSANOW, &old_tio); // Restore terminal mode
                printf("\n[C-Shark] Ctrl+D detected, exiting...\n");
                pcap_breakloop(handle);
                pcap_freecode(&fp);
                pcap_close(handle);
                global_pcap_handle = NULL;
                extern void cleanup_and_exit(void);
                cleanup_and_exit();
            }
        }
        
        // Small delay to prevent busy-waiting
        usleep(1000); // 1ms
    }
    
    // Restore terminal mode
    tcsetattr(STDIN_FILENO, TCSANOW, &old_tio);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    global_pcap_handle = NULL;
    printf("\n[C-Shark] Captured %d packets in this session.\n", packet_counter);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!keep_sniffing) {
        pcap_breakloop((pcap_t *)user_data);
        return;
    }
    
    packet_counter++;
    
    // Store packet
    if (current_session && current_session->packet_count < MAX_PACKETS) {
        store_packet(packet_counter, pkthdr, packet);
    }
    
    // Get link-layer type to determine how to decode
    pcap_t *handle = (pcap_t *)user_data;
    int datalink_type = pcap_datalink(handle);
    
    // Print packet summary with link type info
    print_packet_summary_with_linktype(packet_counter, pkthdr->ts, pkthdr->caplen, packet, datalink_type);
}

void store_packet(int id, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    stored_packet_t *new_packet = (stored_packet_t *)malloc(sizeof(stored_packet_t));
    new_packet->id = id;
    new_packet->timestamp = pkthdr->ts;
    new_packet->length = pkthdr->len;
    new_packet->captured_length = pkthdr->caplen;
    new_packet->data = (u_char *)malloc(pkthdr->caplen);
    memcpy(new_packet->data, packet, pkthdr->caplen);
    new_packet->next = NULL;
    
    if (current_session->head == NULL) {
        current_session->head = new_packet;
        current_session->tail = new_packet;
    } else {
        current_session->tail->next = new_packet;
        current_session->tail = new_packet;
    }
    
    current_session->packet_count++;
}

void free_session(session_t *session) {
    if (!session) return;
    
    stored_packet_t *current = session->head;
    while (current) {
        stored_packet_t *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
    
    free(session);
}

//#########LLM GENERATED CODE ENDS#########