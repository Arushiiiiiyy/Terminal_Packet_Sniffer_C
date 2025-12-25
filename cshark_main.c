//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

// Global variables
volatile int keep_sniffing = 1;
session_t *current_session = NULL;
int packet_counter = 0;

extern pcap_t *global_pcap_handle;
void signal_handler(int sig) {
    if (sig == SIGINT) {
        keep_sniffing = 0;
        printf("\n[C-Shark] Stopping capture... Returning to menu.\n");
        if (global_pcap_handle) {
            pcap_breakloop(global_pcap_handle);
        }
    }
}

void cleanup_and_exit(void) {
    printf("\n[C-Shark] Exiting C-Shark...\n");
    
    // Stop any active capture
    if (global_pcap_handle) {
        pcap_breakloop(global_pcap_handle);
        pcap_close(global_pcap_handle);
        global_pcap_handle = NULL;
    }
    
    // Free session memory
    if (current_session) {
        free_session(current_session);
        current_session = NULL;
    }
    
    exit(0);
}

int main() {
    int option;
    int num = 1;
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");
    
    pcap_if_t *head_dev;
    char errstore[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&head_dev, errstore) == -1) {
        fprintf(stderr, "Error in finding devices: %s\n", errstore);
        exit(1);
    }
    
    if (head_dev == NULL) {
        printf("Sorry, can't find any interfaces, check installation of libpcap\n");
        exit(1);
    }
    
    // List all devices
    pcap_if_t *start_dev = head_dev;
    for (; start_dev != NULL; start_dev = start_dev->next) {
        printf("%d. %s", num++, start_dev->name);
        if (start_dev->description) {
            printf(" (%s)", start_dev->description);
        }
        printf("\n");
    }
    
    printf("\nSelect an interface to sniff (1-%d): ", num - 1);
    int choice;
    if (scanf("%d", &choice) == EOF) {
        cleanup_and_exit();
    }
    int c = getchar();
    if (c == EOF) {
        cleanup_and_exit();
    }

    if (choice <= 0 || choice >= num) {
        printf("Invalid choice\n");
        pcap_freealldevs(head_dev);
        exit(1);
    }
    
    // Find selected device
    int place = 1;
    pcap_if_t *dummy = head_dev;
    const char *selected_name = NULL;
    
    for (; dummy != NULL; dummy = dummy->next) {
        if (place == choice) {
            selected_name = dummy->name;
            break;
        }
        place++;
    }
    
    char *device_copy = strdup(selected_name);
    pcap_freealldevs(head_dev);
    
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", device_copy);
    
    // Main menu loop
    while (1) {
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n\n");
        printf("Choose option: ");
        
        if (scanf("%d", &option) == EOF) {
            cleanup_and_exit();
        }
        int c = getchar();
        if (c == EOF) {
            cleanup_and_exit();
        }
        
        switch (option) {
            case 1:
                // Clear previous session
                if (current_session) {
                    free_session(current_session);
                    current_session = NULL;
                }
                sniff_all(device_copy);
                break;
                
            case 2: {
                // Clear previous session
                if (current_session) {
                    free_session(current_session);
                    current_session = NULL;
                }
                
                printf("\nSelect filter:\n");
                printf("1. HTTP\n");
                printf("2. HTTPS\n");
                printf("3. DNS\n");
                printf("4. ARP\n");
                printf("5. TCP\n");
                printf("6. UDP\n");
                printf("Choice: ");
                
                int filter_choice;
                if (scanf("%d", &filter_choice) == EOF) {
                    cleanup_and_exit();
                }
                int fc = getchar();
                if (fc == EOF) {
                    cleanup_and_exit();
                }

                if (filter_choice >= 1 && filter_choice <= 6) {
                    sniff_filtered(device_copy, filter_choice);
                } else {
                    printf("Invalid filter choice.\n");
                }
                break;
            }
            
            case 3:
                inspect_session();
                break;
                
            case 4:
                printf("[C-Shark] Exiting...\n");
                if (current_session) {
                    free_session(current_session);
                }
                free(device_copy);
                exit(0);
                
            default:
                printf("Invalid option. Please try again.\n");
        }
        
        printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", device_copy);
    }
    
    return 0;
}
//#########LLM GENERATED CODE ENS#########