#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>     /* NEW: needed for select() — enables interactive relay mode */

#define TOR_PROXY_HOST "127.0.0.1"
#define TOR_PROXY_PORT 9050
#define USERNAME       "toralizer"
#define BUFFER_SIZE    4096 /* NEW: buffer size for bidirectional traffic relay */

/* SOCKS4 Response Packet Structure */
struct socks_response {
    uint8_t  version;
    uint8_t  status;
    uint16_t dest_port;
    uint32_t dest_ip;
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        /* NEW: now accepts hostnames, onion addresses, or IPs — Tor resolves them */
        fprintf(stderr, "Usage: %s <target hostname/onion> <target port>\n", argv[0]);
        return 1;
    }

    const char *target_host = argv[1];  /* NEW: renamed from target_ip → target_host for SOCKS4a */
    int target_port = atoi(argv[2]);

    int sock_fd;
    struct sockaddr_in proxy_addr;
    struct socks_response res;

    // Socket creation
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("[-] Socket creation failed");
        return 1;
    }

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(TOR_PROXY_PORT);
    proxy_addr.sin_addr.s_addr = inet_addr(TOR_PROXY_HOST);

    // Connect to the local Tor daemon
    printf("[+] Connecting to Tor proxy at %s:%d...\n", TOR_PROXY_HOST, TOR_PROXY_PORT);
    if (connect(sock_fd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("[-] Connection to Tor failed. Is Tor running?");
        close(sock_fd);
        return 1;
    }

    /*
     * NEW: SOCKS4a Dynamic Handshake Buffer
     *
     * The original code used a fixed struct (userid[8]) which truncated the
     * username and sent a malformed packet — causing the 0x00 rejection seen
     * in the README. This dynamic build fixes that AND upgrades to SOCKS4a:
     *
     * Packet layout: VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID(N)
     *                + NULL(1) + HOSTNAME(M) + NULL(1)
     *
     * Setting DSTIP to 0.0.0.1 signals SOCKS4a mode — Tor reads the
     * hostname appended after USERID and resolves it server-side,
     * preventing DNS leaks on the client.
     */
    size_t packet_size = 9 + strlen(USERNAME) + strlen(target_host);
    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        perror("[-] Memory allocation failed");
        close(sock_fd);
        return 1;
    }

    uint8_t *ptr = packet;
    *ptr++ = 0x04;                                      // VN: SOCKS version 4
    *ptr++ = 0x01;                                      // CD: CONNECT command

    uint16_t port_nbo = htons(target_port);
    memcpy(ptr, &port_nbo, 2); ptr += 2;                // DSTPORT

    uint32_t fake_ip = inet_addr("0.0.0.1");            /* NEW: 0.0.0.x triggers SOCKS4a mode */
    memcpy(ptr, &fake_ip, 4); ptr += 4;                 // DSTIP (Tor ignores this in SOCKS4a)

    strcpy((char *)ptr, USERNAME);                      // USERID (null-terminated — no truncation!)
    ptr += strlen(USERNAME) + 1;

    strcpy((char *)ptr, target_host);                   /* NEW: hostname appended — Tor resolves it */
                                                         // HOSTNAME (avoids DNS leak on client side)

    // Send SOCKS4a handshake
    printf("[+] Sending SOCKS4a handshake for %s:%d (DNS Leak Proof)...\n", target_host, target_port);
    if (write(sock_fd, packet, packet_size) < 0) {
        perror("[-] Failed to send handshake");
        free(packet);
        close(sock_fd);
        return 1;
    }
    free(packet);

    // Read and validate proxy response
    memset(&res, 0, sizeof(res));
    if (read(sock_fd, &res, sizeof(res)) < 0) {
        perror("[-] Failed to read proxy response");
        close(sock_fd);
        return 1;
    }

    // 0x5a status means request granted
    if (res.status != 0x5a) {
        fprintf(stderr, "[-] Tor proxy rejected connection. Status: 0x%02x\n", res.status);
        close(sock_fd);
        return 1;
    }

    /*
     * NEW: Interactive Relay Mode
     *
     * Uses select() to multiplex between stdin and the Tor socket,
     * forwarding data bidirectionally in real time — like a poor man's
     * netcat over Tor. The original code just closed the connection
     * after the handshake; this lets you actually interact with the
     * target service (HTTP, SSH, IRC, etc.).
     */
    printf("[========= SUCCESS =========]\n");
    printf(" Connection established securely via Tor network!\n");
    printf(" Entering interactive relay mode... (Ctrl+C to exit)\n");
    printf("[===========================]\n\n");

    char buffer[BUFFER_SIZE];
    fd_set read_fds;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);  // Monitor keyboard input
        FD_SET(sock_fd, &read_fds);       // Monitor incoming data from the tunnel

        // Block until data is available on either descriptor
        if (select(sock_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("[-] Select error");
            break;
        }

        // User typed something → send through the Tor tunnel to the target
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (bytes_read <= 0) break;

            if (write(sock_fd, buffer, bytes_read) < 0) {
                perror("[-] Failed to write to socket");
                break;
            }
        }

        // Data received from the target server → print to stdout
        if (FD_ISSET(sock_fd, &read_fds)) {
            ssize_t bytes_received = read(sock_fd, buffer, sizeof(buffer));
            if (bytes_received <= 0) {
                printf("\n[+] Remote server closed the connection.\n");
                break;
            }
            write(STDOUT_FILENO, buffer, bytes_received);
        }
    }

    close(sock_fd);
    return 0;
}
