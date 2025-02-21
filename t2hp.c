#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <getopt.h>
#include <sys/select.h>
#include <stdbool.h>

#define BUFFER_SIZE 8192
#define MAX_HOSTNAME 256
#define max(a, b) ((a) > (b) ? (a) : (b))

#define DEFAULT_LOCAL_TCP 9040
#define DEFAULT_LOCAL_UDP 9053
#define DEFAULT_PROXY_HOST "192.168.8.100"
#define DEFAULT_PROXY_PORT 8080
#define DEFAULT_DNS_SERVER "8.8.8.8"

struct proxy_params {
    char remote_host[INET_ADDRSTRLEN];
    int remote_port;
    int local_tcp_port;
    int local_udp_port;
    char dns_server[INET_ADDRSTRLEN];
};

static struct proxy_params global_params;
static bool show_requests = false;

static void parse_dns_name(const unsigned char* packet, size_t pkt_size, char* out, size_t out_size) {
    if (pkt_size < 12) {
        snprintf(out, out_size, "invalid-pkt");
        return;
    }
    size_t pos = 0;
    const unsigned char* ptr = packet + 12;
    while (*ptr) {
        if (pos >= out_size - 1) {
            break;
        }
        if ((*ptr & 0xc0) == 0xc0) {
            snprintf(out, out_size, "compressed");
            return;
        }
        int len = *ptr++;
        if (len < 0) {
            snprintf(out, out_size, "bad-length");
            return;
        }
        if (pos > 0 && pos < out_size - 1) {
            out[pos++] = '.';
        }
        for (int i = 0; i < len; i++) {
            if (pos < out_size - 1 && ptr < packet + pkt_size) {
                out[pos++] = *ptr++;
            } else {
                break;
            }
        }
    }
    if (*ptr == 0) {
        ptr++;
    }
    out[pos] = '\0';
}

void *handle_tcp_connection(void *client_socket) {
    int client_sock = *(int*)client_socket;
    free(client_socket);
    int proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock < 0) {
        perror("Proxy socket creation failed");
        close(client_sock);
        return NULL;
    }
    struct proxy_params *params = &global_params;
    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(params->remote_port);
    inet_pton(AF_INET, params->remote_host, &proxy_addr.sin_addr);
    if (connect(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Proxy connection failed");
        close(client_sock);
        close(proxy_sock);
        return NULL;
    }
    char buffer[BUFFER_SIZE];
    ssize_t bytes;
    bytes = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        send(proxy_sock, buffer, bytes, 0);
        fd_set fds;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_sock, &fds);
            FD_SET(proxy_sock, &fds);
            if (select(max(client_sock, proxy_sock) + 1, &fds, NULL, NULL, NULL) < 0) {
                break;
            }
            if (FD_ISSET(client_sock, &fds)) {
                bytes = recv(client_sock, buffer, BUFFER_SIZE, 0);
                if (bytes <= 0) break;
                send(proxy_sock, buffer, bytes, 0);
            }
            if (FD_ISSET(proxy_sock, &fds)) {
                bytes = recv(proxy_sock, buffer, BUFFER_SIZE, 0);
                if (bytes <= 0) break;
                send(client_sock, buffer, bytes, 0);
            }
        }
    }
    close(client_sock);
    close(proxy_sock);
    return NULL;
}

void start_tcp_server(struct proxy_params *params) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("TCP socket creation failed");
        exit(1);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(params->local_tcp_port);
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP bind failed");
        close(server_sock);
        exit(1);
    }
    if (listen(server_sock, 10) < 0) {
        perror("TCP listen failed");
        close(server_sock);
        exit(1);
    }
    printf("TCP server listening on port %d\n", params->local_tcp_port);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (*client_sock < 0) {
            perror("Accept failed");
            free(client_sock);
            continue;
        }
        pthread_t thread;
        pthread_create(&thread, NULL, handle_tcp_connection, client_sock);
        pthread_detach(thread);
    }
}

void start_udp_server(struct proxy_params *params) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation failed");
        exit(1);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(params->local_udp_port);
    if (bind(udp_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("UDP bind failed");
        close(udp_sock);
        exit(1);
    }
    printf("UDP server (DNS proxy) listening on port %d\n", params->local_udp_port);
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr, dns_addr;
    socklen_t client_len = sizeof(client_addr);
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    inet_pton(AF_INET, params->dns_server, &dns_addr.sin_addr);
    while (1) {
        ssize_t bytes = recvfrom(udp_sock, buffer, BUFFER_SIZE, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
        if (bytes < 0) {
            perror("UDP recvfrom failed");
            continue;
        }
        if (show_requests) {
            char domain[256] = {0};
            parse_dns_name((unsigned char*)buffer, bytes, domain, sizeof(domain));
            char client_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
            if (strcmp(client_ip, params->dns_server) != 0) {
                printf("DNS request from %s -> domain: %s\n", client_ip, domain);
            }
        }
        sendto(udp_sock, buffer, bytes, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr));
        bytes = recvfrom(udp_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytes < 0) {
            perror("UDP recvfrom DNS failed");
            continue;
        }
        sendto(udp_sock, buffer, bytes, 0, (struct sockaddr*)&client_addr, client_len);
    }
}

void print_usage(const char *progname) {
    printf("\nUsage: %s [OPTIONS]\n", progname);
    printf("\n  --local-tcp <port>       TCP port to listen on locally (default %d)\n",
           DEFAULT_LOCAL_TCP);
    printf("  --local-dns <port>       UDP port to listen on locally for DNS (default %d)\n",
           DEFAULT_LOCAL_UDP);
    printf("  --http-proxy <host:port> Remote proxy server (default %s:%d)\n",
           DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT);
    printf("  --dns <ip>               DNS server address (default %s)\n", DEFAULT_DNS_SERVER);
    printf("  --show-requests          Print client IP and requested domain name (DNS)\n");
    printf("  -h, --help               Show this help message\n\n");
    printf("Example:\n");
    printf("  %s --local-tcp 9040 --local-dns 9053 \\\n", progname);
    printf("     --http-proxy 192.168.8.100:8080 --dns 8.8.8.8 --show-requests\n\n");
    printf("This application creates a local TCP proxy on --local-tcp and a DNS proxy on --local-dns.\n");
    printf("TCP connections are forwarded to the specified --http-proxy. DNS queries are forwarded\n");
    printf("to the specified --dns server. With --show-requests you can see DNS queries.\n\n");
}

int main(int argc, char *argv[]) {
    struct proxy_params params;
    strcpy(params.remote_host, DEFAULT_PROXY_HOST);
    params.remote_port = DEFAULT_PROXY_PORT;
    params.local_tcp_port = DEFAULT_LOCAL_TCP;
    params.local_udp_port = DEFAULT_LOCAL_UDP;
    strcpy(params.dns_server, DEFAULT_DNS_SERVER);
    static struct option long_options[] = {
        {"local-tcp",     required_argument, 0, 't'},
        {"local-dns",     required_argument, 0, 'd'},
        {"http-proxy",    required_argument, 0, 'x'},
        {"dns",           required_argument, 0, 'n'},
        {"show-requests", no_argument,       0, 's'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int opt, long_index;
    while ((opt = getopt_long(argc, argv, "ht:d:x:n:s", long_options, &long_index)) != -1) {
        switch (opt) {
            case 't':
                params.local_tcp_port = atoi(optarg);
                break;
            case 'd':
                params.local_udp_port = atoi(optarg);
                break;
            case 'x': {
                char *colon = strchr(optarg, ':');
                if (!colon) {
                    fprintf(stderr, "Invalid --http-proxy format. Use host:port\n");
                    exit(1);
                }
                *colon = '\0';
                strcpy(params.remote_host, optarg);
                params.remote_port = atoi(colon + 1);
                break;
            }
            case 'n':
                strcpy(params.dns_server, optarg);
                break;
            case 's':
                show_requests = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
    global_params = params;
    printf("Starting local TCP proxy on port %d -> %s:%d\n",
           params.local_tcp_port, params.remote_host, params.remote_port);
    printf("Starting local DNS proxy on port %d -> DNS server %s\n",
           params.local_udp_port, params.dns_server);
    if (show_requests) {
        printf("DNS request logging is enabled.\n");
    }
    pthread_t udp_thread;
    pthread_create(&udp_thread, NULL, (void*(*)(void*))start_udp_server, &params);
    pthread_detach(udp_thread);
    start_tcp_server(&params);
    return 0;
}
