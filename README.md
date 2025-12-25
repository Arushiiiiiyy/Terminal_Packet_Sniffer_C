INSTRUCTIONS TO DOWNLOAD libpcap ON MAC-OS
  brew install libpcap<br>


SOME INFORMATION ON OUTPUT
	1) For the hexdump (first 64 bytes) , it shows from Layer 2 .
	2) For the sake of uniformity and wireshark , 
	TCP and UDP terminologies are printed under the same name

**C-Shark** is a command-line packet sniffer built with `libpcap` that captures and analyzes network traffic in real-time.

### Features Implemented

- **Device Discovery** - List all network interfaces and select one to monitor
- **Live Packet Capture** - Real-time packet sniffing with Ctrl+C to stop
- **Layer-by-Layer Decoding:**
  - **L2 (Ethernet)**: MAC addresses, EtherType (IPv4/IPv6/ARP)
  - **L3 (Network)**: IPv4, IPv6, ARP headers with all fields decoded
  - **L4 (Transport)**: TCP and UDP headers with port identification
  - **L7 (Payload)**: Protocol identification (HTTP/HTTPS/DNS), hex dump of first 64 bytes
- **Protocol Filtering** - Filter by HTTP, HTTPS, DNS, ARP, TCP, UDP
- **Session Storage** - Store up to 10,000 packets from last session
- **Packet Inspector** - Deep dive into any captured packet with full hex dump

### Building and Running

```bash
cd B
make
sudo ./cshark
```

**Note:** Root privileges required for packet capture.
