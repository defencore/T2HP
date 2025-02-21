# T2HP - TCP to HTTP Proxy (Burp Suite)

T2HP is a TCP to HTTP proxy designed for Burp Suite, allowing interception of TCP and DNS traffic and forwarding it through an HTTP proxy.

![T2HP Logo](https://github.com/user-attachments/assets/ffa50d90-f24e-4a8f-b615-4b21df316198)

## Prepare Docker Environment

To set up a Docker container with the required dependencies, run:

```sh
sudo docker run -v $(pwd):/app -it ubuntu:22.04
```

Then, inside the container, install the necessary packages and the OpenWRT SDK:

```sh
apt-get update
apt-get install -y \
    wget \
    xz-utils \
    build-essential \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*
```

Download and extract the OpenWRT SDK:

```sh
SDK_URL=https://downloads.openwrt.org/releases/22.03.4/targets/ath79/nand/openwrt-sdk-22.03.4-ath79-nand_gcc-11.2.0_musl.Linux-x86_64.tar.xz
wget $SDK_URL -O /tmp/sdk.tar.xz && \
    mkdir -p /opt/openwrt-sdk && \
    tar -xvf /tmp/sdk.tar.xz -C /opt/openwrt-sdk --strip-components=1 && \
    rm /tmp/sdk.tar.xz
```

Navigate to the OpenWRT SDK directory and install the required feeds:

```sh
cd /opt/openwrt-sdk
./scripts/feeds update -a && ./scripts/feeds install -a
```

## Compiling

To compile `t2hp` for MIPS architecture:

```sh
PATH="/opt/openwrt-sdk/staging_dir/toolchain-mips_24kc_gcc-11.2.0_musl/bin:${PATH}"
export STAGING_DIR="/opt/openwrt-sdk/staging_dir"
mips-openwrt-linux-gcc -o t2hp t2hp.c -pthread -static
mips-openwrt-linux-strip t2hp
```

## Deploy

Transfer the compiled binary to the target OpenWRT device:

```sh
scp /path/to/t2hp root@192.168.8.1:/tmp/
ssh root@192.168.8.1
```

Set up the necessary firewall and NAT rules:

Redirect 80 & 443
```sh
cat << 'EOF' > /etc/firewall.user
nft add table inet t2hp
nft add chain inet t2hp prerouting { type nat hook prerouting priority -100 \; }
# nft add rule inet t2hp prerouting ip saddr 192.168.9.0/24 tcp dport 80 counter dnat to 192.168.9.1:9040 # redirect only 80 TCP
# nft add rule inet t2hp prerouting ip saddr 192.168.9.0/24 tcp dport 443 counter dnat to 192.168.9.1:9040 # redirect only 443 TCP
nft add rule inet t2hp prerouting ip saddr 192.168.9.0/24 ip daddr != 192.168.9.0/24 tcp dport != 9040 counter dnat to 192.168.9.1:9040 # redirect all TCP
nft add rule inet t2hp prerouting ip saddr 192.168.9.0/24 udp dport 53 counter dnat to 192.168.9.1:9053
nft add chain inet t2hp input { type filter hook input priority 0 \; }
nft add rule inet t2hp input ip saddr 192.168.9.0/24 tcp dport 9040 accept
nft add rule inet t2hp input ip saddr 192.168.9.0/24 udp dport 9053 accept
EOF
chmod +x /etc/firewall.user
/etc/firewall.user
```


## Running T2HP

Start `t2hp` on the OpenWRT device:

```
root@GL-XE300:/tmp# ./t2hp -h

Usage: ./t2hp [OPTIONS]

  --local-tcp <port>       TCP port to listen on locally (default 9040)
  --local-dns <port>       UDP port to listen on locally for DNS (default 9053)
  --http-proxy <host:port> Remote proxy server (default 192.168.8.100:8080)
  --dns <ip>               DNS server address (default 8.8.8.8)
  --show-requests          Print client IP and requested domain name (DNS)
  -h, --help               Show this help message

Example:
  ./t2hp --local-tcp 9040 --local-dns 9053 \
     --http-proxy 192.168.8.100:8080 --dns 8.8.8.8 --show-requests

This application creates a local TCP proxy on --local-tcp and a DNS proxy on --local-dns.
TCP connections are forwarded to the specified --http-proxy. DNS queries are forwarded
to the specified --dns server. With --show-requests you can see DNS queries.
```

```sh
./t2hp --local-tcp 9040 --local-dns 9053 --http-proxy 192.168.8.100:8080 --dns 1.1.1.1 --show-requests
```

Example output:

```sh
Starting local TCP proxy on port 9040 -> 192.168.8.100:8080
Starting local DNS proxy on port 9053 -> DNS server 1.1.1.1
DNS and TCP request logging is enabled.
TCP server listening on port 9040
UDP server (DNS proxy) listening on port 9053
DNS request from 192.168.9.100:58227 -> domain: clientservices.googleapis.com
TCP: 192.168.9.100:42004 -> clientservices.googleapis.com:443
DNS request from 192.168.9.100:28069 -> domain: accounts.google.com
TCP: 192.168.9.100:46672 -> accounts.google.com:443
DNS request from 192.168.9.100:37820 -> domain: connectivitycheck.gstatic.com
TCP: 192.168.9.100:37568 -> connectivitycheck.gstatic.com:80
DNS request from 192.168.9.100:35392 -> domain: ifconfig.io
TCP: 192.168.9.100:44902 -> ifconfig.io:443
DNS request from 192.168.9.100:43049 -> domain: a.nel.cloudflare.com
DNS request from 192.168.9.100:27700 -> domain: a.nel.cloudflare.com
```

## License

This project is licensed under the MIT License.

## Author

defencore
