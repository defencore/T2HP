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

```sh
iptables -t nat -F PREROUTING
iptables -F INPUT

iptables -t nat -A PREROUTING -i br-guest -s 192.168.9.0/24 -p tcp -j DNAT --to-destination 192.168.9.1:9040
iptables -A INPUT -i br-guest -p tcp --dport 9040 -j ACCEPT
iptables -t nat -A PREROUTING -i br-guest -s 192.168.9.0/24 -p udp --dport 53 -j DNAT --to-destination 192.168.9.1:9053
iptables -A INPUT -i br-guest -p udp --dport 9053 -j ACCEPT

iptables -t nat -A PREROUTING -i br-guest -s 192.168.9.0/24 -d 192.168.9.0/24 -p tcp -j ACCEPT
iptables -t nat -A PREROUTING -i br-guest -s 192.168.9.0/24 -d 192.168.9.0/24 -p udp ! --dport 53 -j ACCEPT
```

## Running T2HP

Start `t2hp` on the OpenWRT device:

```sh
./t2hp --local-tcp 9040 --local-dns 9053 --http-proxy 192.168.8.100:8080
```

Example output:

```sh
Starting proxy to 192.168.8.100:8080
Local TCP port: 9040, UDP port: 9053
TCP server listening on port 9040
UDP server listening on port 9053
```

## License

This project is licensed under the MIT License.

## Author

Defencore
