// C++ standard libraries
#include <iostream>
#include <string>
#include <cstdint>

// POSIX libraries
#include <arpa/inet.h>
#include <csignal>

// Third-Party libraries
#include <pcap.h>

// Network interface to listen on. Leave empty to auto-select the first available interface.
static const std::string CAPTURE_INTERFACE = "";

// Set to true to capture all traffic on the network, false to capture only traffic addressed to this host
static const bool PROMISCUOUS_MODE = true;

// Global handle used by the signal handler to stop the capture loop cleanly
static pcap_t* g_handle = nullptr;

/**
 * @brief Handles OS signals to stop the capture loop cleanly.
 *
 * @param[in] signal  Signal number received (e.g. SIGINT from Ctrl+C).
 *
 * @note Registered via std::signal before pcap_loop.
 */
void signal_handler(int signal) {
    (void)signal;
    // Request pcap_loop to stop after the current packet
    if (g_handle) pcap_breakloop(g_handle);
}

/**
 * @defgroup NetworkHeaders Network Protocol Headers
 * @brief Packed structs for each TCP/IP layer.
 * @{
 */

// --- Link Layer (TCP/IP Layer 1) ---
struct __attribute__((packed)) EtherHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
};

// --- Internet Layer (TCP/IP Layer 2) ---
struct __attribute__((packed)) IpHeader {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// --- Transport Layer (TCP/IP Layer 3) ---
struct __attribute__((packed)) UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// --- Application Layer (TCP/IP Layer 4) ---
struct __attribute__((packed)) DnsHeader {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions_count;
    uint16_t answers_count;
    uint16_t authority_count;
    uint16_t additional_count;
};

/** @} */

/**
 * @brief Parses a DNS name field from a DNS message, handling pointer compression.
 *
 * @param[in]  dns_header_start  Pointer to the first byte of the DNS message,
 *                               used to resolve compression pointer offsets.
 * @param[in]  current_pos       Pointer to the start of the DNS name field to parse.
 * @param[in]  packet_end        One past the last valid byte of the captured frame.
 * @param[out] out_name          Decoded domain name (e.g. "example.com").
 * @return Bytes consumed at @p current_pos, or -1 if the packet is malformed.
 */
int parse_dns_name_safe(const uint8_t* dns_header_start,
                        const uint8_t* current_pos,
                        const uint8_t* packet_end,
                        std::string& out_name) {

    // Cursor, advances through the name field
    const uint8_t* p = current_pos;

    // How far to advance current_pos after returning
    int bytes_consumed = 0;

    // Counts compression pointer jumps. If non-zero, stops counting bytes_consumed.
    // Exceeding 5 jumps raises an error (possible attack or malformed packet)
    int jump_count = 0;

    // Until the DNS name is fully read, or an error occurs
    while (true) {

        // Bounds check
        if (p >= packet_end) return -1;

        uint8_t len = *p;

        // String finished, DNS name is fully read
        if (len == 0) {

            // Add one more byte for the zero terminator
            if (jump_count == 0) bytes_consumed++;
            break;
        }

        // Compression pointer (2 bytes): signaled by the two top bits being 11 (0xC0)
        // Remaining 14 bits carry the offset into the DNS message
        if ((len & 0xC0) == 0xC0) {

            // Bounds check
            if (p + 1 >= packet_end) return -1;

            // Compute the offset from the remaining 14 bits (6 from first byte + 8 from second)
            uint16_t offset = ((len & 0x3F) << 8) | *(p + 1);

            // If it is the first jump, count the two pointer bytes as consumed
            if (jump_count == 0) bytes_consumed += 2;

            // Jump cursor to the compressed name within the DNS message
            p = dns_header_start + offset;

            // Bounds check
            if (p >= packet_end) return -1;
            jump_count++;

            // Prevent infinite loop on malformed or crafted packets
            if (jump_count > 5) return -1;
            continue;
        }

        // Normal label
        if (p + 1 + len > packet_end) return -1;

        // Append label characters to the output name
        for (int i = 0; i < len; ++i) {
            out_name += static_cast<char>(p[1 + i]);
        }

        // Append dot separator between labels (e.g. "google" + "." + "com")
        out_name += ".";

        // Advance cursor past this label to the next one
        p += (1 + len);
        if (jump_count == 0) bytes_consumed += (1 + len);
    }

    // Remove the trailing dot added after the last label
    if (!out_name.empty() && out_name.back() == '.') {
        out_name.pop_back();
    }

    return bytes_consumed;
}

/**
 * @brief Processes a raw Ethernet frame captured by libpcap.
 *
 * Parses each TCP/IP layer sequentially, discarding the frame if it
 * does not match the expected protocols (Ethernet, IPv4, UDP, DNS).
 * Prints each DNS question found in the frame to stdout.
 *
 * @param[in] args    User-supplied context pointer (unused, required by libpcap callback signature).
 * @param[in] header  Capture metadata provided by libpcap (uses only captured length).
 * @param[in] packet  Pointer to the raw captured frame bytes.
 *
 * @note This function is called automatically by libpcap.
 */
void process_packet(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    const size_t packet_len = header->caplen;

    // One past the last valid byte of the frame, used for bounds checks
    const uint8_t* packet_end = packet + packet_len;

    // --- ETHERNET LAYER ---

    if (packet_len < sizeof(EtherHeader)) return;

    // Map struct onto raw bytes
    const EtherHeader* eth = reinterpret_cast<const EtherHeader*>(packet);

    // Discard if the protocol is not IPv4
    if (ntohs(eth->ether_type) != 0x0800) return;

    // --- IP LAYER ---

    if (packet_len < sizeof(EtherHeader) + sizeof(IpHeader)) return;

    // Map struct onto raw bytes
    const IpHeader* ip = reinterpret_cast<const IpHeader*>(packet + sizeof(EtherHeader));

    // IHL: lower 4 bits of version_ihl, indicates the header length in 32-bit words (minimum 5 = 20 bytes)
    uint8_t ihl = ip->version_ihl & 0x0F;

    // Corrupt or invalid IP header
    if (ihl < 5) return;

    // Actual IP header size in bytes; may exceed sizeof(IpHeader) if options are present
    uint16_t ip_header_len = ihl * 4;

    if (sizeof(EtherHeader) + ip_header_len > packet_len) return;

    // Discard if the protocol is not UDP
    if (ip->protocol != 0x11) return;

    // --- UDP LAYER ---

    uint32_t udp_offset = sizeof(EtherHeader) + ip_header_len;
    if (udp_offset + sizeof(UdpHeader) > packet_len) return;

    // Map struct onto raw bytes
    const UdpHeader* udp = reinterpret_cast<const UdpHeader*>(packet + udp_offset);

    // Discard if neither port is 53 (DNS)
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dst_port = ntohs(udp->dst_port);
    if (src_port != 53 && dst_port != 53) return;

    // --- APPLICATION LAYER (DNS) ---

    uint32_t dns_offset = udp_offset + sizeof(UdpHeader);
    if (dns_offset + sizeof(DnsHeader) > packet_len) return;

    // Base of the DNS message, used to resolve compression pointer offsets
    const uint8_t* dns_header_start = packet + dns_offset;

    // Map struct onto raw bytes
    const DnsHeader* dns = reinterpret_cast<const DnsHeader*>(dns_header_start);

    // Convert from network byte order (big endian) to host byte order
    int question_num = ntohs(dns->questions_count);

    if (question_num == 0) return;

    // Points past the DNS header to the first question entry
    const uint8_t* current_pos = dns_header_start + sizeof(DnsHeader);

    std::cout << "\n[+] DNS packet detected (" << packet_len << " bytes)\n";
    std::cout << "    Questions: " << question_num << "\n";

    for (int i = 0; i < question_num; ++i) {

        std::string domain;
        int bytes_read = parse_dns_name_safe(dns_header_start, current_pos, packet_end, domain);

        if (bytes_read < 0) {
            std::cout << "    [!] Error: malformed name or attack detected.\n";
            return;
        }

        std::cout << "    -> Domain: " << domain << "\n";

        current_pos += bytes_read;

        // Skip Type (2 bytes) and Class (2 bytes) at the end of each question entry
        if (current_pos + 4 > packet_end) return;
        current_pos += 4;
    }
}

/**
 * @brief Entry point. Opens a network interface and captures DNS packets indefinitely.
 *
 * Automatically selects the first available interface if CAPTURE_INTERFACE is not set.
 * Applies a BPF (Berkeley Packet Filter) to discard non-DNS traffic at kernel level,
 * before it reaches userspace. Handles SIGINT (Ctrl+C) to close the handle cleanly.
 *
 * @note Requires root privileges (run with sudo).
 * @note pcap_open_live(device, max_bytes_per_packet, promiscuous_mode, timeout_ms, errbuf)
 */
int main() {

    // errbuf stores errors raised until the handle is open
    char errbuf[PCAP_ERRBUF_SIZE];

    // --- FIND NETWORK INTERFACE ---

    // alldevs: head of the interface linked list. dev: pointer used to traverse it
    pcap_if_t *alldevs, *dev;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding interfaces: " << errbuf << "\n";
        return 1;
    }

    if (alldevs == nullptr) {
        std::cerr << "No network interfaces found.\n";
        return 1;
    }

    if (CAPTURE_INTERFACE.empty()) {
        // No interface specified, auto-select the first available
        dev = alldevs;
    } else {
        // Search for the specified interface
        for (dev = alldevs; dev != nullptr; dev = dev->next) {
            if (std::string(dev->name) == CAPTURE_INTERFACE) break;
        }
        // Specified interface not found, fall back to first available
        if (dev == nullptr) {
            std::cerr << "Warning: interface '" << CAPTURE_INTERFACE << "' not found, falling back to '" << alldevs->name << "'.\n";
            dev = alldevs;
        }
    }

    std::cout << "Listening on interface: " << dev->name << "\n";

    // --- OPEN INTERFACE ---

    // Promiscuous mode captures all traffic on the network, not just traffic addressed to this host
    g_handle = pcap_open_live(dev->name, 65535, PROMISCUOUS_MODE ? 1 : 0, 1000, errbuf);
    if (g_handle == nullptr) {
        std::cerr << "Could not open device " << dev->name << ": " << errbuf << "\n";
        std::cerr << "TIP: Did you run with sudo?\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Free the interface linked list, no longer needed
    pcap_freealldevs(alldevs);

    // --- SIGNAL HANDLER ---

    // Register signal_handler to catch Ctrl+C and stop the capture loop cleanly
    std::signal(SIGINT, signal_handler);

    // --- COMPILE AND APPLY BPF FILTER ---

    // The kernel discards all non-matching packets before they reach userspace
    struct bpf_program fp;
    std::string filter = "udp port 53";
    if (pcap_compile(g_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(g_handle) << "\n";
        return 1;
    }
    if (pcap_setfilter(g_handle, &fp) == -1) {
        std::cerr << "Error applying filter: " << pcap_geterr(g_handle) << "\n";
        return 1;
    }

    // --- CAPTURE LOOP ---

    // pcap_loop calls process_packet for every packet that passes the BPF filter
    std::cout << "Starting DNS capture... (Press Ctrl+C to exit)\n";
    pcap_loop(g_handle, 0, process_packet, nullptr);

    // --- CLEANUP ---

    pcap_close(g_handle);
    return 0;
}
