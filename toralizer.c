#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#define TOR_PROXY_HOST "127.0.0.1"
#define TOR_PROXY_PORT 9050
#define USERNAME       "toralizer"

// SOCKS4 request packet structure
struct socks_request {
    uint8_t version;
    uint8_t cmd;
    uint16_t dest_port;
    uint32_t dest_ip;
    unsigned char userid[8];
};

// SOCKS4 response packet structure
struct socks_response {
    uint8_t version;
    uint8_t status;
    uint16_t dest_port;
    uint32_t dest_ip;
};

int main(int argc, chat *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <target IP> <target PORT> \n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    int sock_fd;
    struct sockaddr_in proxy_addr;
    struct socks_request req;
    struct socks_response res;

    // socket creation
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(TOR_PROXY_PORT);
    proxy_addr.sin_addr.s_addr = inet_addr(TOR_PROXY_HOST);

    // connect to the local tor deomon running on the system/container
    printf("[+] Connecting to Tor proxy at %s:%d...\n", TOR_PROXY_HOST, TOR_PROXY_PORT);
    if (connect(sock_fd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Connection to Tor failed. Check if Tor is running");
        close(sock_fd);
        return 1;
    }

    // build the socks4 request
    req.version = 0x04;
    req.cmd = 0x01;
    req.dest_port = htons(target_port);
    req.dest_ip = htons(target_ip);
    strncpy((char *)req.userid, USERNAME, sizeof(req.userid));

    // send the request packet to Tor
    printf("[+] Sending SOCKS4 handshake for target %s:%d...\n", target_ip, target_port);
    if (write(sock_fd, &req, sizeof(req)) < 0) {
        perror("Failed to send handshake");
        close(sock_fd);
        return 1;
    }

    // read Tors response
    memset(&res, 0, sizeof(res));
    if (read(sock_fd, &res, sizeof(res)) < 0) {
        perror("Failed to read proxy response");
        close(sock_fd);
        return 1;
    }

    // validate the response status
    // 0x5a status means request granted
    if (res.status == 0x5a) {
        printf("[========= SUCCESS =========]\n");
        printf(" Successfully proxied through Tor to %s:%d!\n", target_ip, target_port);
        printf(" You can now read/write securely using socket file descriptor: %d\n", sock_fd);
        printf("[===========================]\n");
    } else {
        fprintf(stderr, "[-] Tor proxy rejected the connection. Status code: 0x%02x\n", res.status);
        close(sock_fd);
        return 1;
    }

    // Clean up
    close(sock_fd);
    return 0;
}
