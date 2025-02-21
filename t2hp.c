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
#include <ctype.h>

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

struct tcp_client_info {
    int client_sock;
    struct sockaddr_in client_addr;
};

static struct proxy_params global_params;
static bool show_requests = false;

static char *my_strcasestr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t needle_len = strlen(needle);
    if (!needle_len) return (char*)haystack;
    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, needle_len) == 0) {
            return (char*)haystack;
        }
    }
    return NULL;
}

static void parse_dns_name(const unsigned char* packet, size_t pkt_size, char* out, size_t out_size) {
    if (pkt_size < 12) {
        snprintf(out, out_size, "invalid-pkt");
        return;
    }
    size_t pos = 0;
    const unsigned char* ptr = packet + 12;
    while (*ptr) {
        if (pos >= out_size - 1) break;
        if ((*ptr & 0xc0) == 0xc0) {
            snprintf(out, out_size, "compressed");
            return;
        }
        int len = *ptr++;
        if (len < 0) {
            snprintf(out, out_size, "bad-length");
            return;
        }
        if (pos > 0 && pos < out_size - 1) out[pos++] = '.';
        for (int i = 0; i < len; i++) {
            if (pos < out_size - 1 && ptr < packet + pkt_size) {
                out[pos++] = *ptr++;
            } else {
                break;
            }
        }
    }
    if (*ptr == 0) ptr++;
    out[pos] = '\0';
}

static void parse_http_domain_port(const char *data, char *domain, size_t dsize, int *port) {
    const char *connect = "CONNECT ";
    const char *host_hdr = "Host:";
    const char *p;
    *port = 80;

    if (!strncmp(data, connect, strlen(connect))) {
        p = data + strlen(connect);
        while (*p && (*p == ' ')) p++;
        snprintf(domain, dsize, "%s", p);
        char *sp = strchr(domain, ' ');
        if (sp) *sp = '\0';
        sp = strchr(domain, '\r');
        if (sp) *sp = '\0';
        sp = strchr(domain, '\n');
        if (sp) *sp = '\0';
        if ((sp = strchr(domain, ':'))) {
            *port = atoi(sp + 1);
            *sp = '\0';
        } else {
            *port = 443;
        }
        return;
    }

    p = my_strcasestr(data, host_hdr);
    if (p) {
        p += strlen(host_hdr);
        while (*p && (*p == ' ' || *p == '\t')) p++;
        snprintf(domain, dsize, "%s", p);
        char *sp = strchr(domain, '\r');
        if (sp) *sp = '\0';
        sp = strchr(domain, '\n');
        if (sp) *sp = '\0';
        if ((sp = strchr(domain, ':'))) {
            *port = atoi(sp + 1);
            *sp = '\0';
        }
    }
}

static bool parse_tls_sni(const unsigned char *data, size_t len, char *out, size_t out_size, int *port) {
    if (len < 5) return false;
    if (data[0] != 0x16) return false;
    if (data[1] != 0x03) return false;
    int tls_len = (data[3] << 8) + data[4];
    if (tls_len < 0 || tls_len + 5 > (int)len) return false;
    const unsigned char *p = data + 5;
    int handshake_len = tls_len;
    if (handshake_len < 4) return false;
    if (p[0] != 0x01) return false;
    int ch_len = (p[1] << 16) | (p[2] << 8) | p[3];
    if (ch_len < 0 || ch_len + 4 > handshake_len) return false;
    p += 4;
    handshake_len -= 4;
    if (handshake_len < 34) return false;
    p += 34;
    handshake_len -= 34;
    if (handshake_len < 1) return false;
    int session_id_len = p[0];
    if (session_id_len < 0 || session_id_len + 1 > handshake_len) return false;
    p += 1 + session_id_len;
    handshake_len -= 1 + session_id_len;
    if (handshake_len < 2) return false;
    int cipher_len = (p[0] << 8) | p[1];
    if (cipher_len < 0 || cipher_len + 2 > handshake_len) return false;
    p += 2 + cipher_len;
    handshake_len -= 2 + cipher_len;
    if (handshake_len < 1) return false;
    int comp_len = p[0];
    if (comp_len < 0 || comp_len + 1 > handshake_len) return false;
    p += 1 + comp_len;
    handshake_len -= 1 + comp_len;
    if (handshake_len < 2) return false;
    int ext_len = (p[0] << 8) | p[1];
    p += 2;
    handshake_len -= 2;
    if (ext_len < 0 || ext_len > handshake_len) return false;
    while (ext_len >= 4) {
        int ext_type = (p[0] << 8) | p[1];
        int ext_size = (p[2] << 8) | p[3];
        p += 4;
        ext_len -= 4;
        if (ext_size < 0 || ext_size > ext_len) return false;
        if (ext_type == 0x0000) {
            const unsigned char *server_name_list = p + 2;
            int server_name_list_len = (p[0] << 8) | p[1];
            if (server_name_list_len <= ext_size - 2 && server_name_list_len > 3) {
                if (server_name_list[0] == 0x00) {
                    int name_len = (server_name_list[1] << 8) | server_name_list[2];
                    if (name_len > 0 && name_len <= server_name_list_len - 3) {
                        if (name_len >= (int)out_size) name_len = out_size - 1;
                        memcpy(out, &server_name_list[3], name_len);
                        out[name_len] = '\0';
                        *port = 443;
                        return true;
                    }
                }
            }
        }
        p += ext_size;
        ext_len -= ext_size;
    }
    return false;
}

void *handle_tcp_connection(void *arg) {
    struct tcp_client_info info = *(struct tcp_client_info*)arg;
    free(arg);
    int client_sock = info.client_sock;
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
    ssize_t bytes = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

    if (bytes > 0) {
        buffer[bytes] = '\0';

        if (show_requests) {
            char domain[256] = "unknown";
            int port = 0;
            parse_http_domain_port(buffer, domain, sizeof(domain), &port);
            if (!strcmp(domain, "unknown")) {
                if (parse_tls_sni((unsigned char*)buffer, bytes, domain, sizeof(domain), &port)) {
                }
            }
            if (!port) port = 80;
            char client_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &info.client_addr.sin_addr, client_ip, sizeof(client_ip));
            printf("TCP: %s:%d -> %s:%d\n",
                   client_ip, ntohs(info.client_addr.sin_port),
                   domain, port);
        }
        send(proxy_sock, buffer, bytes, 0);

        fd_set fds;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_sock, &fds);
            FD_SET(proxy_sock, &fds);
            if (select(max(client_sock, proxy_sock) + 1, &fds, NULL, NULL, NULL) < 0) break;
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
    int on = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
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
        int client_fd = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }
        struct tcp_client_info *info = malloc(sizeof(*info));
        info->client_sock = client_fd;
        memcpy(&info->client_addr, &client_addr, sizeof(client_addr));
        pthread_t thread;
        pthread_create(&thread, NULL, handle_tcp_connection, info);
        pthread_detach(thread);
    }
}

void start_udp_server(struct proxy_params *params) {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("UDP socket creation failed");
        exit(1);
    }
    int on = 1;
    setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
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
                printf("DNS request from %s:%d -> domain: %s\n",
                       client_ip, ntohs(client_addr.sin_port), domain);
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
    printf("\n  --local-tcp <port>       TCP port to listen on locally (default %d)\n", DEFAULT_LOCAL_TCP);
    printf("  --local-dns <port>       UDP port to listen on locally for DNS (default %d)\n", DEFAULT_LOCAL_UDP);
    printf("  --http-proxy <host:port> Remote proxy server (default %s:%d)\n", DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT);
    printf("  --dns <ip>               DNS server address (default %s)\n", DEFAULT_DNS_SERVER);
    printf("  --show-requests          Print logs of DNS/TCP connections with domain and port if possible\n");
    printf("  -h, --help               Show this help message\n\n");
    printf("Example:\n");
    printf("  %s --local-tcp 9040 --local-dns 9053 --http-proxy 192.168.8.100:8080 --dns 8.8.8.8 --show-requests\n\n",
           progname);
    printf("TCP output:   TCP: <client_ip>:<client_port> -> <domain>:<port>\n");
    printf("DNS output:   DNS request from <client_ip>:<client_port> -> domain: <domain>\n");
    printf("Domain might remain 'unknown' if we can't parse HTTP/HTTPS headers or SNI.\n\n");
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
        printf("DNS and TCP request logging is enabled.\n");
    }

    pthread_t udp_thread;
    pthread_create(&udp_thread, NULL, (void*(*)(void*))start_udp_server, &params);
    pthread_detach(udp_thread);

    start_tcp_server(&params);
    return 0;
}
