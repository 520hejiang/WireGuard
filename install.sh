#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PURPLE="\033[35m"
CYAN="\033[36m"
PLAIN="\033[0m"

red() { echo -e "${RED}$1${PLAIN}"; }
green() { echo -e "${GREEN}$1${PLAIN}"; }
yellow() { echo -e "${YELLOW}$1${PLAIN}"; }
blue() { echo -e "${BLUE}$1${PLAIN}"; }
purple() { echo -e "${PURPLE}$1${PLAIN}"; }
cyan() { echo -e "${CYAN}$1${PLAIN}"; }

# 配置目录
WG_DIR="/etc/wireguard"
CLIENT_DIR="/root/wireguard-clients"
LOG_DIR="/var/log/wireguard"
NGINX_CONF_DIR="/etc/nginx"

# 网络配置
VPN_NET="10.66.66.0/24"
VPN_INTERFACE="wg0"

[[ $EUID -ne 0 ]] && red "[!] 请使用 root 用户运行本脚本！" && exit 1

# 显示抗封锁选项菜单
show_stealth_menu() {
    clear
    cyan "========================================"
    cyan "    WireGuard 抗封锁配置选择"
    cyan "========================================"
    echo ""
    yellow "请选择抗封锁方案："
    echo ""
    echo "1) UDP over TCP 隧道 (udp2raw)"
    echo "2) WebSocket 隧道 (wstunnel)" 
    echo "3) HTTPS 伪装 (nginx + 证书)"
    echo "4) 端口跳跃 + 混淆"
    echo "5) Shadowsocks 前置代理"
    echo "6) 混合隐身模式 (推荐)"
    echo ""
    read -rp "请选择 [1-6, 默认6]: " STEALTH_MODE
    STEALTH_MODE=${STEALTH_MODE:-6}
    
    case $STEALTH_MODE in
        1) setup_udp2raw ;;
        2) setup_wstunnel ;;
        3) setup_https_camouflage ;;
        4) setup_port_hopping ;;
        5) setup_shadowsocks_proxy ;;
        6) setup_hybrid_stealth ;;
        *) yellow "[*] 使用默认混合隐身模式"; setup_hybrid_stealth ;;
    esac
}

# 检测系统
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        SYSTEM="$ID"
        VERSION="$VERSION_ID"
    else
        red "[!] 无法检测系统类型"
        exit 1
    fi

    case $SYSTEM in
        "ubuntu"|"debian")
            PKG_MANAGER="apt"
            PKG_INSTALL="apt install -y"
            PKG_UPDATE="apt update -y && apt upgrade -y"
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum update -y"
            if [[ $SYSTEM == "centos" ]]; then
                PKG_INSTALL="yum install -y epel-release && yum install -y"
            fi
            ;;
        *)
            red "[!] 不支持的系统: $SYSTEM"
            exit 1
            ;;
    esac

    yellow "[*] 检测到系统: $SYSTEM $VERSION"
}

# 安装依赖和混淆工具
install_dependencies() {
    yellow "[*] 安装依赖包和隐身工具..."
    
    #   $PKG_UPDATE
    
    # 基础工具
    case $SYSTEM in
        "ubuntu"|"debian")
            $PKG_INSTALL wireguard wireguard-tools linux-headers-$(uname -r) \
                         curl wget unzip qrencode nginx certbot python3-certbot-nginx \
                         ufw fail2ban jq bc net-tools dnsutils openssl socat cron \
                         build-essential git cmake libssl-dev nodejs npm iptables-persistent \
                         obfs4proxy shadowsocks-libev simple-obfs python3-pip
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            $PKG_INSTALL wireguard-tools kernel-devel-$(uname -r) \
                         curl wget unzip qrencode nginx certbot python3-certbot-nginx \
                         firewalld fail2ban jq bc net-tools bind-utils openssl socat \
                         gcc git cmake openssl-devel nodejs npm iptables-services \
                         python3-pip
            ;;
    esac
    
    # 安装额外混淆工具
    pip3 install shadowsocks wstunnel
    
    # 安装 udp2raw (UDP over TCP 工具)
    install_udp2raw
    
    # 配置 fail2ban
    setup_fail2ban_protection
}

# 安装 udp2raw
install_udp2raw() {
    yellow "[*] 安装 udp2raw..."
    
    cd /tmp || exit 1
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_NAME="amd64" ;;
        aarch64) ARCH_NAME="arm64" ;;
        armv7l) ARCH_NAME="arm" ;;
        *) red "[!] 不支持的架构: $ARCH"; return 1 ;;
    esac
    
    # 下载 udp2raw
    wget -O udp2raw "https://github.com/wangyu-/udp2raw/releases/latest/download/udp2raw_binaries.tar.gz"
    tar -xzf udp2raw_binaries.tar.gz
    
    # 查找对应架构的二进制文件
    UDP2RAW_BIN=$(find . -name "*${ARCH_NAME}*" -type f | head -1)
    if [[ -n "$UDP2RAW_BIN" ]]; then
        chmod +x "$UDP2RAW_BIN"
        mv "$UDP2RAW_BIN" /usr/local/bin/udp2raw
        green "[*] udp2raw 安装成功"
    else
        yellow "[!] udp2raw 安装失败，跳过该功能"
    fi
    
    rm -rf /tmp/udp2raw*
}

# 配置 fail2ban 防护
setup_fail2ban_protection() {
    if ! systemctl is-active --quiet fail2ban; then
        systemctl enable --now fail2ban
        
        # WireGuard 防护规则
        cat > /etc/fail2ban/filter.d/wireguard.conf <<EOF
[Definition]
failregex = .*Invalid handshake initiation from <HOST>.*
            .*Handshake did not complete after .* seconds, retrying.*
            .*Receiving handshake initiation from unknown peer <HOST>.*
ignoreregex =
EOF

        cat > /etc/fail2ban/jail.d/wireguard.conf <<EOF
[wireguard]
enabled = true
port = 51820,443,80,8080
filter = wireguard
logpath = $LOG_DIR/wireguard.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
        
        systemctl restart fail2ban
    fi
}

# 获取服务器 IP
get_server_ip() {
    yellow "[*] 获取服务器公网 IP..."
    
    IP_SOURCES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
        "https://ifconfig.me/ip"
    )
    
    for source in "${IP_SOURCES[@]}"; do
        SERVER_IP=$(curl -s --connect-timeout 5 --max-time 10 "$source" 2>/dev/null | grep -E '^[0-9.]+$')
        [[ -n "$SERVER_IP" ]] && break
    done
    
    if [[ -z "$SERVER_IP" ]]; then
        red "[!] 无法获取服务器公网 IP"
        exit 1
    fi
    
    yellow "[*] 服务器 IP: $SERVER_IP"
}

# 方案1: UDP over TCP 隧道
setup_udp2raw() {
    yellow "[*] 配置 UDP over TCP 隧道..."
    
    WG_PORT=51820
    TCP_PORT=443
    RAW_PASSWORD=$(openssl rand -base64 16)
    
    STEALTH_CONFIG="udp2raw"
    
    yellow "[*] WireGuard 端口: $WG_PORT"
    yellow "[*] TCP 伪装端口: $TCP_PORT"
    yellow "[*] 隧道密码: $RAW_PASSWORD"
    
    # 保存配置
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=udp2raw
WG_PORT=$WG_PORT
TCP_PORT=$TCP_PORT
RAW_PASSWORD=$RAW_PASSWORD
EOF
}

# 方案2: WebSocket 隧道
setup_wstunnel() {
    yellow "[*] 配置 WebSocket 隧道..."
    
    WG_PORT=51820
    WS_PORT=8080
    HTTPS_PORT=443
    
    STEALTH_CONFIG="wstunnel"
    
    yellow "[*] WireGuard 端口: $WG_PORT"
    yellow "[*] WebSocket 端口: $WS_PORT"
    yellow "[*] HTTPS 端口: $HTTPS_PORT"
    
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=wstunnel
WG_PORT=$WG_PORT
WS_PORT=$WS_PORT
HTTPS_PORT=$HTTPS_PORT
EOF
}

# 方案3: HTTPS 伪装
setup_https_camouflage() {
    yellow "[*] 配置 HTTPS 伪装..."
    
    read -rp "请输入你的域名 (可选): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        # 生成假域名
        FAKE_DOMAINS=(
            "wg-$(openssl rand -hex 4).example.com"
            "vpn-$(openssl rand -hex 4).cloudflare.com"
            "secure-$(openssl rand -hex 4).github.io"
        )
        DOMAIN=${FAKE_DOMAINS[$((RANDOM % ${#FAKE_DOMAINS[@]}))]}
        USE_REAL_DOMAIN=false
        yellow "[*] 生成伪装域名: $DOMAIN"
    else
        USE_REAL_DOMAIN=true
    fi
    
    WG_PORT=51820
    HTTPS_PORT=443
    
    STEALTH_CONFIG="https"
    
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=https
WG_PORT=$WG_PORT
HTTPS_PORT=$HTTPS_PORT
DOMAIN=$DOMAIN
USE_REAL_DOMAIN=$USE_REAL_DOMAIN
EOF
}

# 方案4: 端口跳跃
setup_port_hopping() {
    yellow "[*] 配置端口跳跃..."
    
    # 生成随机端口池
    PORTS=($(shuf -i 10000-65000 -n 8 | sort -n))
    PRIMARY_PORT=${PORTS[0]}
    WG_PORT=$PRIMARY_PORT
    
    STEALTH_CONFIG="port_hop"
    
    yellow "[*] 端口池: ${PORTS[*]}"
    
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=port_hop
PORTS=(${PORTS[*]})
WG_PORT=$WG_PORT
EOF
}

# 方案5: Shadowsocks 前置代理
setup_shadowsocks_proxy() {
    yellow "[*] 配置 Shadowsocks 前置代理..."
    
    WG_PORT=51820
    SS_PORT=8388
    SS_PASSWORD=$(openssl rand -base64 16)
    SS_METHOD="chacha20-ietf-poly1305"
    
    STEALTH_CONFIG="shadowsocks"
    
    yellow "[*] Shadowsocks 端口: $SS_PORT"
    yellow "[*] 加密方法: $SS_METHOD"
    
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=shadowsocks
WG_PORT=$WG_PORT
SS_PORT=$SS_PORT
SS_PASSWORD=$SS_PASSWORD
SS_METHOD=$SS_METHOD
EOF
}

# 方案6: 混合隐身模式
setup_hybrid_stealth() {
    yellow "[*] 配置混合隐身模式..."
    
    # 组合多种技术
    WG_PORT=51820
    TCP_PORT=443
    WS_PORT=8080
    SS_PORT=8388
    
    RAW_PASSWORD=$(openssl rand -base64 16)
    SS_PASSWORD=$(openssl rand -base64 16)
    SS_METHOD="chacha20-ietf-poly1305"
    
    # 随机端口池
    PORTS=($(shuf -i 20000-60000 -n 5))
    
    STEALTH_CONFIG="hybrid"
    
    yellow "[*] 混合模式已激活"
    yellow "[*] TCP 伪装: $TCP_PORT"
    yellow "[*] WebSocket: $WS_PORT"  
    yellow "[*] Shadowsocks: $SS_PORT"
    yellow "[*] 端口池: ${PORTS[*]}"
    
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=hybrid
WG_PORT=$WG_PORT
TCP_PORT=$TCP_PORT
WS_PORT=$WS_PORT
SS_PORT=$SS_PORT
RAW_PASSWORD=$RAW_PASSWORD
SS_PASSWORD=$SS_PASSWORD
SS_METHOD=$SS_METHOD
PORTS=(${PORTS[*]})
EOF
}

# 生成 WireGuard 密钥
generate_keys() {
    yellow "[*] 生成 WireGuard 密钥..."
    
    mkdir -p "$WG_DIR" "$CLIENT_DIR" "$LOG_DIR"
    
    # 生成服务器密钥对
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # 生成预共享密钥 (增强安全性)
    PRESHARED_KEY=$(wg genpsk)
    
    yellow "[*] 服务器公钥: $SERVER_PUBLIC_KEY"
    
    # 保存密钥
    cat > "$WG_DIR/keys.txt" <<EOF
Server Private Key: $SERVER_PRIVATE_KEY
Server Public Key: $SERVER_PUBLIC_KEY
Preshared Key: $PRESHARED_KEY
Generated: $(date)
EOF
    chmod 600 "$WG_DIR/keys.txt"
}

# 配置 WireGuard 服务器
configure_wireguard_server() {
    yellow "[*] 配置 WireGuard 服务器..."
    
    # 加载隐身配置
    source "$WG_DIR/stealth.conf"
    
    # 生成服务器配置
    cat > "$WG_DIR/$VPN_INTERFACE.conf" <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = ${VPN_NET%.*}.1/24
ListenPort = $WG_PORT
SaveConfig = false

# 网络优化
MTU = 1420
PreUp = echo 'WireGuard Starting' >> $LOG_DIR/wireguard.log
PostUp = iptables -A FORWARD -i $VPN_INTERFACE -j ACCEPT; iptables -A FORWARD -o $VPN_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o \$(ip route | grep default | awk '{print \$5}' | head -n1) -j MASQUERADE
PostUp = echo 'WireGuard Started' >> $LOG_DIR/wireguard.log
PreDown = iptables -D FORWARD -i $VPN_INTERFACE -j ACCEPT; iptables -D FORWARD -o $VPN_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o \$(ip route | grep default | awk '{print \$5}' | head -n1) -j MASQUERADE
PostDown = echo 'WireGuard Stopped' >> $LOG_DIR/wireguard.log

# 日志记录
#LogLevel = verbose

EOF

    chmod 600 "$WG_DIR/$VPN_INTERFACE.conf"
    
    # 启用 IP 转发
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p
}

# 部署隐身层
deploy_stealth_layer() {
    yellow "[*] 部署隐身层..."
    
    source "$WG_DIR/stealth.conf"
    
    case $STEALTH_MODE in
        "udp2raw")
            deploy_udp2raw_tunnel
            ;;
        "wstunnel")
            deploy_wstunnel
            ;;
        "https")
            deploy_https_camouflage
            ;;
        "port_hop")
            deploy_port_hopping
            ;;
        "shadowsocks")
            deploy_shadowsocks
            ;;
        "hybrid")
            deploy_all_stealth_methods
            ;;
    esac
}

# 部署 UDP2RAW 隧道
deploy_udp2raw_tunnel() {
    if [[ -f /usr/local/bin/udp2raw ]]; then
        # 创建 UDP2RAW 服务
        cat > /etc/systemd/system/udp2raw.service <<EOF
[Unit]
Description=UDP2RAW Tunnel
After=network.target
Wants=wireguard-wg0.service

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -s -l0.0.0.0:$TCP_PORT -r127.0.0.1:$WG_PORT -k "$RAW_PASSWORD" --raw-mode faketcp -a
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable udp2raw
    fi
}

# 部署 WebSocket 隧道
deploy_wstunnel() {
    # 安装 wstunnel
    npm install -g wstunnel
    
    # 创建 wstunnel 服务
    cat > /etc/systemd/system/wstunnel.service <<EOF
[Unit]
Description=WebSocket Tunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/node $(npm root -g)/wstunnel/bin/wstunnel -s $WS_PORT --udp-forward=127.0.0.1:$WG_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable wstunnel
}

# 部署 HTTPS 伪装
deploy_https_camouflage() {
    if [[ "$USE_REAL_DOMAIN" == "true" ]]; then
        # 申请真实证书
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN"
    else
        # 生成自签名证书
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "/etc/ssl/private/$DOMAIN.key" \
                -out "/etc/ssl/certs/$DOMAIN.crt" \
                -subj "/C=US/ST=CA/L=San Francisco/O=Tech Corp/CN=$DOMAIN"
    fi
    
    # 配置 Nginx
    cat > "/etc/nginx/sites-available/wireguard-stealth" <<EOF
upstream wireguard {
    server 127.0.0.1:$WG_PORT;
}

server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen $HTTPS_PORT ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate ${USE_REAL_DOMAIN:+/etc/letsencrypt/live/$DOMAIN/fullchain.pem};
    ssl_certificate_key ${USE_REAL_DOMAIN:+/etc/letsencrypt/live/$DOMAIN/privkey.pem};
    ${USE_REAL_DOMAIN:+ssl_certificate /etc/ssl/certs/$DOMAIN.crt;}
    ${USE_REAL_DOMAIN:+ssl_certificate_key /etc/ssl/private/$DOMAIN.key;}
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # 伪装成正常网站
    location / {
        proxy_pass https://www.cloudflare.com;
        proxy_set_header Host www.cloudflare.com;
        proxy_ssl_server_name on;
    }
    
    # WireGuard UDP over HTTP 隧道
    location /wg-tunnel {
        proxy_pass http://127.0.0.1:$WG_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/wireguard-stealth /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
}

# 部署端口跳跃
deploy_port_hopping() {
    # 创建端口跳跃脚本
    cat > /usr/local/bin/wg-port-hop.sh <<EOF
#!/bin/bash

PORTS=(${PORTS[*]})
WG_INTERFACE="$VPN_INTERFACE"
CURRENT_PORT=\$(wg show \$WG_INTERFACE listen-port 2>/dev/null)

# 选择新端口
for port in "\${PORTS[@]}"; do
    if [[ "\$port" != "\$CURRENT_PORT" ]]; then
        # 停止服务
        wg-quick down \$WG_INTERFACE 2>/dev/null
        
        # 更新端口
        sed -i "s/ListenPort = .*/ListenPort = \$port/" /etc/wireguard/\$WG_INTERFACE.conf
        
        # 重启服务
        wg-quick up \$WG_INTERFACE
        
        # 更新防火墙
        ufw delete allow \$CURRENT_PORT/udp 2>/dev/null
        ufw allow \$port/udp
        
        echo "\$(date): WireGuard port hopped to \$port" >> $LOG_DIR/port-hop.log
        break
    fi
done
EOF
    
    chmod +x /usr/local/bin/wg-port-hop.sh
    
    # 添加定时端口跳跃 (每2小时)
    (crontab -l 2>/dev/null; echo "0 */2 * * * /usr/local/bin/wg-port-hop.sh") | crontab -
}

# 部署 Shadowsocks
deploy_shadowsocks() {
    # 配置 Shadowsocks 服务器
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": $SS_PORT,
    "password": "$SS_PASSWORD",
    "timeout": 300,
    "method": "$SS_METHOD",
    "fast_open": true,
    "mode": "tcp_and_udp",
    "plugin": "obfs-server",
    "plugin_opts": "obfs=tls;failover=127.0.0.1:$WG_PORT"
}
EOF

    systemctl enable --now shadowsocks-libev
}

# 部署所有隐身方法 (混合模式)
deploy_all_stealth_methods() {
    yellow "[*] 部署混合隐身层..."
    
    # 部署所有方法
    deploy_udp2raw_tunnel
    deploy_wstunnel  
    deploy_shadowsocks
    deploy_port_hopping
    
    # 创建智能路由
    create_intelligent_routing
}

# 创建智能路由
create_intelligent_routing() {
    cat > /usr/local/bin/wg-smart-route.sh <<'EOF'
#!/bin/bash

# 根据网络状况自动选择最佳隧道
check_tunnel_health() {
    local tunnel=$1
    local port=$2
    
    # 简单连通性检查
    timeout 5 nc -u -z 127.0.0.1 $port 2>/dev/null
    return $?
}

# 检查所有隧道健康状况
if check_tunnel_health "wireguard" "$WG_PORT"; then
    echo "$(date): Direct WireGuard OK" >> /var/log/wireguard/routing.log
elif check_tunnel_health "udp2raw" "$TCP_PORT"; then
    echo "$(date): Using UDP2RAW tunnel" >> /var/log/wireguard/routing.log
elif check_tunnel_health "shadowsocks" "$SS_PORT"; then
    echo "$(date): Using Shadowsocks tunnel" >> /var/log/wireguard/routing.log  
else
    echo "$(date): All tunnels down, attempting recovery" >> /var/log/wireguard/routing.log
    systemctl restart wg-quick@wg0
fi
EOF
    
    chmod +x /usr/local/bin/wg-smart-route.sh
    
    # 每5分钟检查一次
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/wg-smart-route.sh") | crontab -
}

# 配置防火墙
configure_firewall() {
    yellow "[*] 配置防火墙..."
    
    source "$WG_DIR/stealth.conf"
    
    # UFW 配置
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        
        # 根据隐身模式开放端口
        case $STEALTH_MODE in
            "udp2raw"|"hybrid")
                ufw allow $TCP_PORT comment 'UDP2RAW TCP'
                ;;
            "wstunnel"|"hybrid")
                ufw allow $WS_PORT comment 'WebSocket'
                ufw allow $HTTPS_PORT comment 'HTTPS'
                ;;
            "https")
                ufw allow 80 comment 'HTTP'
                ufw allow $HTTPS_PORT comment 'HTTPS'
                ;;
            "port_hop"|"hybrid")
                for port in "${PORTS[@]}"; do
                    ufw allow $port/udp comment "WG-Hop-$port"
                done
                ;;
            "shadowsocks"|"hybrid")
                ufw allow $SS_PORT comment 'Shadowsocks'
                ;;
            *)
                ufw allow $WG_PORT/udp comment 'WireGuard'
                ;;
        esac
        
        ufw --force enable
    fi
    
    # iptables 基础规则
    iptables -I INPUT -p udp --dport $WG_PORT -j ACCEPT
    iptables -I FORWARD -i $VPN_INTERFACE -j ACCEPT
    iptables -I FORWARD -o $VPN_INTERFACE -j ACCEPT
    iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
}

# 启动 WireGuard 服务
start_wireguard_service() {
    yellow "[*] 启动 WireGuard 服务..."
    
    # 启用 WireGuard 内核模块
    modprobe wireguard
    
    # 启动服务
    wg-quick up $VPN_INTERFACE
    
    # 设置开机自启
    systemctl enable wg-quick@$VPN_INTERFACE
    
    # 启动隐身层服务
    source "$WG_DIR/stealth.conf"
    case $STEALTH_MODE in
        "udp2raw"|"hybrid")
            systemctl start udp2raw
            ;;
        "wstunnel"|"hybrid")  
            systemctl start wstunnel
            ;;
        "shadowsocks"|"hybrid")
            systemctl start shadowsocks-libev
            ;;
    esac
    
    # 验证服务状态
    if wg show $VPN_INTERFACE &>/dev/null; then
        green "[*] WireGuard 服务启动成功"
    else
        red "[!] WireGuard 服务启动失败"
        exit 1
    fi
}

# 生成客户端配置
generate_client_config() {
    local client_name="${1:-client-$(date +%s)}"
    
    yellow "[*] 生成客户端配置: $client_name"
    
    # 生成客户端密钥对
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # 分配客户端 IP
    CLIENT_COUNT=$(grep -c "PublicKey" "$WG_DIR/$VPN_INTERFACE.conf" 2>/dev/null || echo "0")
    CLIENT_IP="${VPN_NET%.*}.$((CLIENT_COUNT + 2))/32"
    
    source "$WG_DIR/stealth.conf"
    
    # 添加客户端到服务器配置
    cat >> "$WG_DIR/$VPN_INTERFACE.conf" <<EOF

# Client: $client_name
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_IP%/*}/32
EOF

    # 重载 WireGuard 配置
    wg syncconf $VPN_INTERFACE <(wg-quick strip $VPN_INTERFACE)
    
    # 根据隐身模式生成不同的客户端配置
    case $STEALTH_MODE in
        "udp2raw"|"hybrid")
            generate_udp2raw_client_config "$client_name"
            ;;
        "wstunnel"|"hybrid")
            generate_wstunnel_client_config "$client_name"
            ;;
        "https")
            generate_https_client_config "$client_name"
            ;;
        "port_hop"|"hybrid")
            generate_port_hop_client_config "$client_name"
            ;;
        "shadowsocks"|"hybrid")
            generate_shadowsocks_client_config "$client_name"
            ;;
        *)
            generate_standard_client_config "$client_name"
            ;;
    esac
    
    green "[*] 客户端 $client_name 配置生成完成"
}

# 标准客户端配置
generate_standard_client_config() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name.conf"
    
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 600 "$config_file"
    
    # 生成二维码
    qrencode -t ANSIUTF8 < "$config_file" > "$CLIENT_DIR/$client_name-qr.txt"
}

# UDP2RAW 客户端配置
generate_udp2raw_client_config() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name-udp2raw.conf"
    
    # 标准 WireGuard 配置 (连接本地 UDP2RAW)
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = 127.0.0.1:3333
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # UDP2RAW 客户端脚本
    cat > "$CLIENT_DIR/$client_name-udp2raw.sh" <<EOF
#!/bin/bash

# UDP2RAW 客户端启动脚本
echo "启动 UDP2RAW 客户端..."

# 检查是否已安装 udp2raw
if ! command -v udp2raw &> /dev/null; then
    echo "请先安装 udp2raw 客户端"
    echo "下载地址: https://github.com/wangyu-/udp2raw/releases"
    exit 1
fi

# 启动 UDP2RAW 隧道
udp2raw -c -l127.0.0.1:3333 -r$SERVER_IP:$TCP_PORT -k "$RAW_PASSWORD" --raw-mode faketcp &
UDP2RAW_PID=\$!

echo "UDP2RAW 隧道已启动 (PID: \$UDP2RAW_PID)"
echo "现在可以连接 WireGuard 了"

# 等待中断信号
trap "kill \$UDP2RAW_PID; echo 'UDP2RAW 隧道已关闭'" EXIT
wait \$UDP2RAW_PID
EOF

    chmod +x "$CLIENT_DIR/$client_name-udp2raw.sh"
    chmod 600 "$config_file"
    
    green "[*] UDP2RAW 客户端配置: $config_file"
    green "[*] 启动脚本: $CLIENT_DIR/$client_name-udp2raw.sh"
}

# WebSocket 客户端配置
generate_wstunnel_client_config() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name-wstunnel.conf"
    
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1380

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = 127.0.0.1:4444
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # WebSocket 客户端脚本
    cat > "$CLIENT_DIR/$client_name-wstunnel.sh" <<EOF
#!/bin/bash

echo "启动 WebSocket 隧道..."

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "请先安装 Node.js"
    exit 1
fi

# 安装 wstunnel (如果未安装)
if ! npm list -g wstunnel &>/dev/null; then
    echo "安装 wstunnel..."
    npm install -g wstunnel
fi

# 启动 WebSocket 客户端隧道
wstunnel -t 4444:127.0.0.1:$WG_PORT ws://$SERVER_IP:$WS_PORT &
WSTUNNEL_PID=\$!

echo "WebSocket 隧道已启动 (PID: \$WSTUNNEL_PID)"

trap "kill \$WSTUNNEL_PID; echo 'WebSocket 隧道已关闭'" EXIT
wait \$WSTUNNEL_PID
EOF

    chmod +x "$CLIENT_DIR/$client_name-wstunnel.sh"
    chmod 600 "$config_file"
}

# Shadowsocks 客户端配置
generate_shadowsocks_client_config() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name-ss.conf"
    
    # WireGuard 配置
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1380

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = 127.0.0.1:5555
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Shadowsocks 配置
    cat > "$CLIENT_DIR/$client_name-ss.json" <<EOF
{
    "server": "$SERVER_IP",
    "server_port": $SS_PORT,
    "local_address": "127.0.0.1",
    "local_port": 5555,
    "password": "$SS_PASSWORD",
    "timeout": 300,
    "method": "$SS_METHOD",
    "plugin": "obfs-local",
    "plugin_opts": "obfs=tls;obfs-host=www.cloudflare.com"
}
EOF

    chmod 600 "$config_file" "$CLIENT_DIR/$client_name-ss.json"
}

# 端口跳跃客户端配置
generate_port_hop_client_config() {
    local client_name="$1"
    
    for i in "${!PORTS[@]}"; do
        local port="${PORTS[$i]}"
        local config_file="$CLIENT_DIR/$client_name-port$((i+1)).conf"
        
        cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = $SERVER_IP:$port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
        chmod 600 "$config_file"
    done
    
    green "[*] 端口跳跃配置已生成 (${#PORTS[@]} 个文件)"
}

# HTTPS 伪装客户端配置
generate_https_client_config() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name-https.conf"
    
    cat > "$config_file" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = $DOMAIN:$HTTPS_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 600 "$config_file"
}

# 系统优化
optimize_system() {
    yellow "[*] 优化系统性能..."
    
    # 网络参数优化
    cat >> /etc/sysctl.conf <<EOF

# WireGuard 网络优化
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 4096
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
fs.file-max = 1048576

# WireGuard 特定优化
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
EOF

    sysctl -p
    
    # 文件描述符限制
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
}

# 创建管理工具
create_management_tools() {
    yellow "[*] 创建管理工具..."
    
    cat > /usr/local/bin/wg-mgr <<'EOF'
#!/bin/bash

WG_DIR="/etc/wireguard"
CLIENT_DIR="/root/wireguard-clients"
LOG_DIR="/var/log/wireguard"
VPN_INTERFACE="wg0"

show_status() {
    echo "=== WireGuard 服务状态 ==="
    systemctl status wg-quick@$VPN_INTERFACE --no-pager -l
    echo ""
    echo "=== 接口状态 ==="
    wg show $VPN_INTERFACE 2>/dev/null || echo "接口未启动"
    echo ""
    echo "=== 连接统计 ==="
    wg show $VPN_INTERFACE transfer 2>/dev/null | while read -r pubkey rx tx; do
        echo "客户端 ${pubkey:0:16}... 下载: $(numfmt --to=iec $rx)B 上传: $(numfmt --to=iec $tx)B"
    done
    echo ""
    echo "=== 系统资源 ==="
    echo "CPU: $(top -bn1 | grep Cpu | awk '{print $2}')"
    echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "网络: $(cat /sys/class/net/$VPN_INTERFACE/statistics/rx_bytes 2>/dev/null | numfmt --to=iec || echo "0")B 接收"
}

show_config() {
    echo "=== 服务器配置 ==="
    if [[ -f "$WG_DIR/stealth.conf" ]]; then
        source "$WG_DIR/stealth.conf"
        echo "隐身模式: $STEALTH_MODE"
        case $STEALTH_MODE in
            udp2raw|hybrid)
                echo "TCP 端口: $TCP_PORT"
                echo "UDP2RAW 状态: $(systemctl is-active udp2raw 2>/dev/null || echo "未运行")"
                ;;
            wstunnel|hybrid)
                echo "WebSocket 端口: $WS_PORT"
                echo "WSTunnel 状态: $(systemctl is-active wstunnel 2>/dev/null || echo "未运行")"
                ;;
            shadowsocks|hybrid)
                echo "Shadowsocks 端口: $SS_PORT"
                echo "SS 状态: $(systemctl is-active shadowsocks-libev 2>/dev/null || echo "未运行")"
                ;;
            port_hop|hybrid)
                echo "端口池: ${PORTS[*]}"
                ;;
        esac
    fi
    echo ""
    echo "=== 客户端列表 ==="
    wg show $VPN_INTERFACE peers 2>/dev/null | while read -r pubkey; do
        allowed_ips=$(wg show $VPN_INTERFACE allowed-ips | grep "$pubkey" | awk '{print $2}')
        echo "公钥: ${pubkey:0:32}... IP: $allowed_ips"
    done
}

add_client() {
    if [[ -z "$1" ]]; then
        echo "用法: wg-mgr add-client <客户端名>"
        return 1
    fi
    
    local client_name="$1"
    
    # 检查是否已存在
    if [[ -f "$CLIENT_DIR/$client_name.conf" ]]; then
        echo "❌ 客户端 $client_name 已存在"
        return 1
    fi
    
    # 生成配置 (这里调用主脚本中的函数)
    bash -c "source $(dirname $0)/../wireguard_install.sh && generate_client_config $client_name"
    
    echo "✅ 客户端 $client_name 添加成功"
    echo "配置文件: $CLIENT_DIR/$client_name*.conf"
}

remove_client() {
    if [[ -z "$1" ]]; then
        echo "用法: wg-mgr remove-client <客户端名>"
        return 1
    fi
    
    local client_name="$1"
    local config_files=($CLIENT_DIR/$client_name*.conf)
    
    if [[ ! -f "${config_files[0]}" ]]; then
        echo "❌ 客户端 $client_name 不存在"
        return 1
    fi
    
    # 从服务器配置中移除客户端
    # 这里需要根据公钥移除，实际实现会更复杂
    echo "移除客户端功能开发中..."
    
    # 删除配置文件
    rm -f $CLIENT_DIR/$client_name*
    
    echo "✅ 客户端 $client_name 已移除"
}

show_qr() {
    if [[ -z "$1" ]]; then
        echo "用法: wg-mgr qr <客户端名>"
        return 1
    fi
    
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name.conf"
    
    if [[ -f "$config_file" ]]; then
        echo "=== $client_name 二维码 ==="
        qrencode -t ANSIUTF8 < "$config_file"
    else
        echo "❌ 配置文件不存在: $config_file"
    fi
}

view_logs() {
    case "$1" in
        wireguard|"")
            echo "=== WireGuard 日志 ==="
            journalctl -u wg-quick@$VPN_INTERFACE --no-pager -n 50
            ;;
        stealth)
            echo "=== 隐身层日志 ==="
            if [[ -f "$WG_DIR/stealth.conf" ]]; then
                source "$WG_DIR/stealth.conf"
                case $STEALTH_MODE in
                    udp2raw|hybrid)
                        journalctl -u udp2raw --no-pager -n 20
                        ;;
                    wstunnel|hybrid)
                        journalctl -u wstunnel --no-pager -n 20
                        ;;
                    shadowsocks|hybrid)
                        journalctl -u shadowsocks-libev --no-pager -n 20
                        ;;
                esac
            fi
            ;;
        live)
            echo "=== 实时日志 ==="
            journalctl -u wg-quick@$VPN_INTERFACE -f
            ;;
    esac
}

restart_service() {
    echo "重启 WireGuard 服务..."
    wg-quick down $VPN_INTERFACE 2>/dev/null
    wg-quick up $VPN_INTERFACE
    
    if wg show $VPN_INTERFACE &>/dev/null; then
        echo "✅ WireGuard 服务重启成功"
    else
        echo "❌ WireGuard 服务重启失败"
    fi
    
    # 重启隐身层
    if [[ -f "$WG_DIR/stealth.conf" ]]; then
        source "$WG_DIR/stealth.conf"
        case $STEALTH_MODE in
            udp2raw|hybrid)
                systemctl restart udp2raw
                ;;
            wstunnel|hybrid)
                systemctl restart wstunnel
                ;;
            shadowsocks|hybrid)
                systemctl restart shadowsocks-libev
                ;;
        esac
        echo "✅ 隐身层服务已重启"
    fi
}

case "$1" in
    status|st)
        show_status
        ;;
    config|cfg)
        show_config
        ;;
    add-client)
        add_client "$2"
        ;;
    remove-client|rm-client)
        remove_client "$2"
        ;;
    qr)
        show_qr "$2"
        ;;
    logs|log)
        view_logs "$2"
        ;;
    restart|rs)
        restart_service
        ;;
    *)
        echo "WireGuard 隐身版管理工具"
        echo ""
        echo "用法: wg-mgr {command} [options]"
        echo ""
        echo "命令:"
        echo "  status / st        查看服务状态"
        echo "  config / cfg       查看配置信息"
        echo "  add-client <n>     添加客户端"
        echo "  remove-client <n>  删除客户端"
        echo "  qr <client>        显示二维码"
        echo "  logs / log         查看日志 (wireguard/stealth/live)"
        echo "  restart / rs       重启服务"
        ;;
esac
EOF

    chmod +x /usr/local/bin/wg-mgr
}

# 生成使用说明
generate_documentation() {
    cat > "$CLIENT_DIR/README.txt" <<EOF
WireGuard 隐身版使用说明
========================

服务器信息:
- IP: $SERVER_IP
- 网段: $VPN_NET
- 隐身模式: $STEALTH_CONFIG

管理命令:
- 服务状态: wg-mgr status
- 添加客户端: wg-mgr add-client <名称>
- 删除客户端: wg-mgr remove-client <名称>
- 显示二维码: wg-mgr qr <客户端名>
- 查看日志: wg-mgr logs
- 重启服务: wg-mgr restart

客户端配置:
根据隐身模式，客户端配置位于 $CLIENT_DIR/ 目录
- 标准模式: client.conf
- UDP2RAW: client-udp2raw.conf + 启动脚本
- WebSocket: client-wstunnel.conf + 启动脚本
- Shadowsocks: client-ss.conf + client-ss.json
- 端口跳跃: 多个 client-portN.conf 文件

客户端软件推荐:
- Windows: WireGuard for Windows
- macOS: WireGuard for macOS
- iOS: WireGuard (App Store)
- Android: WireGuard (Google Play)
- Linux: wireguard-tools

抗封锁建议:
1. 根据网络环境选择合适的隐身模式
2. 定期更换端口 (端口跳跃模式自动)
3. 避免大流量下载引起注意
4. 配合其他协议使用提高成功率

故障排除:
1. 检查服务状态: systemctl status wg-quick@wg0
2. 查看详细日志: journalctl -u wg-quick@wg0 -f
3. 验证网络连通: ping $(echo $VPN_NET | cut -d/ -f1 | sed 's/0$/1/')
4. 重置配置: wg-quick down wg0 && wg-quick up wg0

生成时间: $(date)
EOF

    chmod 600 "$CLIENT_DIR/README.txt"
}

# 主安装流程
main() {
    cyan "========================================"
    cyan "    WireGuard 隐身增强版安装脚本"
    cyan "========================================"
    
    detect_system
    install_dependencies
    get_server_ip
    show_stealth_menu
    generate_keys
    configure_wireguard_server
    deploy_stealth_layer
    configure_firewall
    start_wireguard_service
    
    # 生成默认客户端
    generate_client_config "client1"
    
    optimize_system
    create_management_tools
    generate_documentation
    
    green "\n========================================"
    green "    WireGuard 隐身版安装成功! ✅"
    green "========================================"
    echo ""
    yellow "服务器配置:"
    echo "  IP地址: $SERVER_IP"
    echo "  网段: $VPN_NET"
    echo "  隐身模式: $STEALTH_CONFIG"
    
    source "$WG_DIR/stealth.conf" 2>/dev/null
    case $STEALTH_MODE in
        udp2raw|hybrid)
            echo "  TCP 伪装端口: $TCP_PORT"
            ;;
        wstunnel|hybrid)
            echo "  WebSocket 端口: $WS_PORT"
            echo "  HTTPS 端口: $HTTPS_PORT"
            ;;
        https)
            echo "  HTTPS 端口: $HTTPS_PORT"
            echo "  伪装域名: $DOMAIN"
            ;;
        port_hop|hybrid)
            echo "  端口池: ${PORTS[*]}"
            ;;
        shadowsocks|hybrid)
            echo "  Shadowsocks 端口: $SS_PORT"
            ;;
    esac
    
    echo ""
    yellow "客户端配置:"
    echo "  配置目录: $CLIENT_DIR/"
    echo "  默认客户端: client1"
    echo "  使用说明: $CLIENT_DIR/README.txt"
    echo ""
    yellow "管理命令:"
    echo "  wg-mgr status     - 查看状态"
    echo "  wg-mgr add-client - 添加客户端"
    echo "  wg-mgr qr client1 - 显示二维码"
    echo ""
    green "WireGuard 隐身版已准备就绪！"
    echo "========================================"
}

# 执行主函数
main "$@"
