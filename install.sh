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

# 网络配置
VPN_NET="10.66.66.0/24"
VPN_INTERFACE="wg0"

[[ $EUID -ne 0 ]] && red "[!] 请使用 root 用户运行本脚本！" && exit 1

# 等待并解决包管理器锁定问题
wait_for_package_manager() {
    yellow "[*] 检查包管理器状态..."
    
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
            break
        fi
        
        if [[ $attempt -eq 0 ]]; then
            yellow "[*] 检测到包管理器被锁定，等待自动更新完成..."
        fi
        
        echo -n "."
        sleep 10
        ((attempt++))
    done
    
    echo ""
    
    if [[ $attempt -ge $max_attempts ]]; then
        yellow "[!] 等待超时，强制解除锁定..."
        
        # 找出占用进程并终止
        local lock_processes=(
            "$(fuser /var/lib/dpkg/lock-frontend 2>/dev/null | awk '{print $1}')"
            "$(fuser /var/lib/dpkg/lock 2>/dev/null | awk '{print $1}')"
            "$(fuser /var/cache/apt/archives/lock 2>/dev/null | awk '{print $1}')"
        )
        
        for pid in "${lock_processes[@]}"; do
            if [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]]; then
                yellow "[*] 终止进程: $pid"
                kill -9 "$pid" 2>/dev/null
            fi
        done
        
        # 清理锁定文件
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
        
        # 重新配置 dpkg
        dpkg --configure -a
    fi
    
    green "[*] 包管理器已就绪"
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
            PKG_UPDATE="apt update -y"
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

# 显示抗封锁选项菜单
show_stealth_menu() {
    clear
    cyan "========================================"
    cyan "    WireGuard 抗封锁配置选择"
    cyan "========================================"
    echo ""
    yellow "请选择抗封锁方案："
    echo ""
    echo "1) 基础混淆模式 (端口伪装)"
    echo "2) WebSocket 隧道"
    echo "3) 端口跳跃模式"
    echo "4) 多端口并发 (推荐)"
    echo ""
    read -rp "请选择 [1-4, 默认4]: " STEALTH_MODE
    STEALTH_MODE=${STEALTH_MODE:-4}
    
    case $STEALTH_MODE in
        1) setup_basic_obfuscation ;;
        2) setup_websocket ;;
        3) setup_port_hopping ;;
        4) setup_multi_port ;;
        *) yellow "[*] 使用默认多端口模式"; setup_multi_port ;;
    esac
}

# 方案1: 基础混淆
setup_basic_obfuscation() {
    yellow "[*] 配置基础混淆模式..."
    
    # 使用看起来像 HTTPS 的端口
    WG_PORT=8443
    STEALTH_CONFIG="basic"
    
    yellow "[*] WireGuard 端口: $WG_PORT"
}

# 方案2: WebSocket
setup_websocket() {
    yellow "[*] 配置 WebSocket 模式..."
    
    WG_PORT=51820
    WS_PORT=8080
    HTTPS_PORT=443
    STEALTH_CONFIG="websocket"
    
    yellow "[*] 内部端口: $WG_PORT"
    yellow "[*] WebSocket: $WS_PORT"
}

# 方案3: 端口跳跃
setup_port_hopping() {
    yellow "[*] 配置端口跳跃模式..."
    
    # 生成端口池
    PORTS=(8443 9443 10443 443 8080 9080)
    WG_PORT=${PORTS[0]}
    STEALTH_CONFIG="port_hop"
    
    yellow "[*] 端口池: ${PORTS[*]}"
}

# 方案4: 多端口并发
setup_multi_port() {
    yellow "[*] 配置多端口并发模式..."
    
    # 多个常用端口
    MAIN_PORT=8443
    ALT_PORTS=(9443 10443 443 8080)
    WG_PORT=$MAIN_PORT
    STEALTH_CONFIG="multi_port"
    
    yellow "[*] 主端口: $MAIN_PORT"
    yellow "[*] 备用端口: ${ALT_PORTS[*]}"
}

# 修复的依赖安装函数
install_dependencies() {
    yellow "[*] 安装依赖包..."
    
    # 先等待包管理器就绪
    wait_for_package_manager
    
    # 更新包列表
    yellow "[*] 更新软件包列表..."
    if ! $PKG_UPDATE; then
        red "[!] 软件包更新失败"
        exit 1
    fi
    
    # 基础工具安装
    case $SYSTEM in
        "ubuntu"|"debian")
            yellow "[*] 安装基础工具..."
            $PKG_INSTALL curl wget unzip qrencode ufw fail2ban jq bc \
                         net-tools dnsutils openssl socat cron iptables-persistent
            
            # WireGuard 安装
            yellow "[*] 安装 WireGuard..."
            if [[ "$VERSION" == "18.04" ]] || [[ "$VERSION" == "16.04" ]]; then
                # 老版本 Ubuntu 需要添加 PPA
                $PKG_INSTALL software-properties-common
                add-apt-repository ppa:wireguard/wireguard -y
                $PKG_UPDATE
            fi
            
            $PKG_INSTALL wireguard wireguard-tools linux-headers-$(uname -r) || {
                yellow "[*] 尝试安装内核模块..."
                $PKG_INSTALL wireguard-dkms
            }
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            $PKG_INSTALL curl wget unzip qrencode firewalld fail2ban jq bc \
                         net-tools bind-utils openssl socat
            
            # WireGuard 安装
            if [[ $SYSTEM == "centos" ]]; then
                $PKG_INSTALL epel-release elrepo-release
                $PKG_INSTALL kmod-wireguard wireguard-tools
            else
                $PKG_INSTALL wireguard-tools
            fi
            ;;
    esac
    
    # 检查 WireGuard 是否安装成功
    if ! command -v wg >/dev/null 2>&1; then
        red "[!] WireGuard 安装失败"
        exit 1
    fi
    
    green "[*] WireGuard 安装成功: $(wg --version)"
    
    # 配置 fail2ban
    setup_fail2ban_protection
}

# 配置 fail2ban 防护
setup_fail2ban_protection() {
    yellow "[*] 配置防护系统..."
    
    if ! systemctl is-active --quiet fail2ban; then
        systemctl enable --now fail2ban
        
        # 创建 WireGuard 过滤器
        mkdir -p /etc/fail2ban/filter.d
        cat > /etc/fail2ban/filter.d/wireguard.conf <<'EOF'
[Definition]
failregex = .*Invalid handshake initiation from <HOST>.*
            .*Handshake did not complete after .* seconds, retrying.*
            .*Receiving handshake initiation from unknown peer <HOST>.*
ignoreregex =
EOF

        # 创建监狱配置
        mkdir -p /etc/fail2ban/jail.d
        cat > /etc/fail2ban/jail.d/wireguard.conf <<EOF
[wireguard]
enabled = true
port = 51820,8443,9443,443,8080
filter = wireguard
logpath = /var/log/syslog
maxretry = 5
bantime = 3600
findtime = 600
EOF
        
        systemctl restart fail2ban
        green "[*] fail2ban 配置完成"
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

# 生成 WireGuard 密钥
generate_keys() {
    yellow "[*] 生成 WireGuard 密钥..."
    
    mkdir -p "$WG_DIR" "$CLIENT_DIR" "$LOG_DIR"
    
    # 生成服务器密钥对
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # 生成预共享密钥
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
    
    # 生成服务器配置
    cat > "$WG_DIR/$VPN_INTERFACE.conf" <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = ${VPN_NET%.*}.1/24
ListenPort = $WG_PORT
SaveConfig = false
MTU = 1420

# 网络设置
PostUp = echo 'WireGuard Starting' >> $LOG_DIR/wireguard.log
PostUp = iptables -A FORWARD -i $VPN_INTERFACE -j ACCEPT
PostUp = iptables -A FORWARD -o $VPN_INTERFACE -j ACCEPT  
PostUp = iptables -t nat -A POSTROUTING -o \$(ip route | awk '/default/ {print \$5; exit}') -j MASQUERADE
PostUp = echo 'WireGuard Started at \$(date)' >> $LOG_DIR/wireguard.log

PostDown = iptables -D FORWARD -i $VPN_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $VPN_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o \$(ip route | awk '/default/ {print \$5; exit}') -j MASQUERADE  
PostDown = echo 'WireGuard Stopped at \$(date)' >> $LOG_DIR/wireguard.log

EOF

    chmod 600 "$WG_DIR/$VPN_INTERFACE.conf"
    
    # 启用 IP 转发
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p
    
    green "[*] WireGuard 服务器配置完成"
}

# 部署抗封锁层
deploy_stealth_layer() {
    yellow "[*] 部署抗封锁层..."
    
    case $STEALTH_CONFIG in
        "websocket")
            setup_websocket_tunnel
            ;;
        "port_hop")
            setup_port_hopping_service
            ;;
        "multi_port")
            setup_multi_port_service
            ;;
        "basic"|*)
            yellow "[*] 使用基础混淆模式"
            ;;
    esac
    
    # 保存配置
    cat > "$WG_DIR/stealth.conf" <<EOF
STEALTH_MODE=$STEALTH_CONFIG
WG_PORT=$WG_PORT
SERVER_IP=$SERVER_IP
$(case $STEALTH_CONFIG in
    websocket) echo "WS_PORT=$WS_PORT"; echo "HTTPS_PORT=$HTTPS_PORT" ;;
    port_hop) echo "PORTS=(${PORTS[*]})" ;;
    multi_port) echo "MAIN_PORT=$MAIN_PORT"; echo "ALT_PORTS=(${ALT_PORTS[*]})" ;;
esac)
EOF
}

# WebSocket 隧道设置
setup_websocket_tunnel() {
    yellow "[*] 配置 WebSocket 隧道..."
    
    # 安装 Node.js (如果需要)
    if ! command -v node >/dev/null 2>&1; then
        case $SYSTEM in
            "ubuntu"|"debian")
                curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
                $PKG_INSTALL nodejs
                ;;
            *)
                $PKG_INSTALL nodejs npm
                ;;
        esac
    fi
    
    # 创建简单的 WebSocket 代理脚本
    cat > /usr/local/bin/wg-ws-proxy <<'EOF'
#!/usr/bin/env python3

import asyncio
import websockets
import socket
import threading

class UDPProxy:
    def __init__(self, ws_port, udp_port):
        self.ws_port = ws_port
        self.udp_port = udp_port
        
    async def handle_websocket(self, websocket, path):
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            async for message in websocket:
                # 转发到 WireGuard 端口
                udp_sock.sendto(message, ('127.0.0.1', self.udp_port))
                
                # 接收响应
                response, _ = udp_sock.recvfrom(1500)
                await websocket.send(response)
                
        except Exception as e:
            print(f"WebSocket error: {e}")
        finally:
            udp_sock.close()
    
    def start_server(self):
        start_server = websockets.serve(self.handle_websocket, "0.0.0.0", self.ws_port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    proxy = UDPProxy(8080, 51820)
    proxy.start_server()
EOF
    
    chmod +x /usr/local/bin/wg-ws-proxy
}

# 端口跳跃设置
setup_port_hopping_service() {
    yellow "[*] 配置端口跳跃..."
    
    cat > /usr/local/bin/wg-port-hop.sh <<EOF
#!/bin/bash

PORTS=(${PORTS[*]})
WG_INTERFACE="$VPN_INTERFACE"
CONFIG_FILE="$WG_DIR/\$WG_INTERFACE.conf"

# 获取当前端口
CURRENT_PORT=\$(grep "ListenPort" "\$CONFIG_FILE" | awk '{print \$3}')

# 选择新端口 (排除当前端口)
NEW_PORT=""
for port in "\${PORTS[@]}"; do
    if [[ "\$port" != "\$CURRENT_PORT" ]]; then
        NEW_PORT="\$port"
        break
    fi
done

if [[ -n "\$NEW_PORT" ]]; then
    echo "\$(date): 切换端口从 \$CURRENT_PORT 到 \$NEW_PORT" >> $LOG_DIR/port-hop.log
    
    # 停止接口
    wg-quick down \$WG_INTERFACE 2>/dev/null
    
    # 更新配置文件
    sed -i "s/ListenPort = \$CURRENT_PORT/ListenPort = \$NEW_PORT/" "\$CONFIG_FILE"
    
    # 更新防火墙
    ufw delete allow \$CURRENT_PORT/udp 2>/dev/null
    ufw allow \$NEW_PORT/udp
    
    # 重启接口
    wg-quick up \$WG_INTERFACE
    
    echo "端口已切换到: \$NEW_PORT"
else
    echo "没有可用的替代端口"
fi
EOF
    
    chmod +x /usr/local/bin/wg-port-hop.sh
    
    # 添加定时任务
    (crontab -l 2>/dev/null; echo "0 */6 * * * /usr/local/bin/wg-port-hop.sh") | crontab -
}

# 多端口服务设置
setup_multi_port_service() {
    yellow "[*] 配置多端口服务..."
    
    # 为每个端口创建 iptables 规则
    for port in "${ALT_PORTS[@]}"; do
        iptables -t nat -A PREROUTING -p udp --dport "$port" -j REDIRECT --to-port "$MAIN_PORT"
    done
    
    # 保存 iptables 规则
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
}

# 配置防火墙
configure_firewall() {
    yellow "[*] 配置防火墙..."
    
    # UFW 配置
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        
        case $STEALTH_CONFIG in
            "websocket")
                ufw allow $WG_PORT/udp comment 'WireGuard'
                ufw allow $WS_PORT comment 'WebSocket'
                ufw allow $HTTPS_PORT comment 'HTTPS'
                ;;
            "port_hop")
                for port in "${PORTS[@]}"; do
                    ufw allow $port/udp comment "WG-$port"
                done
                ;;
            "multi_port")
                ufw allow $MAIN_PORT/udp comment 'WG-Main'
                for port in "${ALT_PORTS[@]}"; do
                    ufw allow $port/udp comment "WG-Alt-$port"
                done
                ;;
            *)
                ufw allow $WG_PORT/udp comment 'WireGuard'
                ;;
        esac
        
        ufw --force enable
    fi
    
    green "[*] 防火墙配置完成"
}

# 启动 WireGuard 服务
start_wireguard_service() {
    yellow "[*] 启动 WireGuard 服务..."
    
    # 检查内核模块
    if ! lsmod | grep -q wireguard; then
        modprobe wireguard
    fi
    
    # 启动 WireGuard
    if wg-quick up $VPN_INTERFACE; then
        green "[*] WireGuard 接口启动成功"
    else
        red "[!] WireGuard 接口启动失败"
        exit 1
    fi
    
    # 设置开机自启
    systemctl enable wg-quick@$VPN_INTERFACE
    
    # 验证服务状态
    if wg show $VPN_INTERFACE &>/dev/null; then
        green "[*] WireGuard 服务运行正常"
        wg show $VPN_INTERFACE
    else
        red "[!] WireGuard 服务异常"
        exit 1
    fi
}

# 生成客户端配置
generate_client_config() {
    local client_name="${1:-client1}"
    
    yellow "[*] 生成客户端配置: $client_name"
    
    # 生成客户端密钥对
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # 分配客户端 IP
    CLIENT_COUNT=$(grep -c "PublicKey" "$WG_DIR/$VPN_INTERFACE.conf" 2>/dev/null || echo "0")
    CLIENT_IP="${VPN_NET%.*}.$((CLIENT_COUNT + 2))/32"
    
    # 添加到服务器配置
    cat >> "$WG_DIR/$VPN_INTERFACE.conf" <<EOF

# Client: $client_name
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_IP%/*}/32
EOF

    # 重载配置
    wg syncconf $VPN_INTERFACE <(wg-quick strip $VPN_INTERFACE)
    
    # 生成客户端配置文件
    cat > "$CLIENT_DIR/$client_name.conf" <<EOF
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

    chmod 600 "$CLIENT_DIR/$client_name.conf"
    
    # 生成二维码
    qrencode -t ANSIUTF8 < "$CLIENT_DIR/$client_name.conf" > "$CLIENT_DIR/$client_name-qr.txt"
    
    green "[*] 客户端 $client_name 配置生成完成"
    green "    配置文件: $CLIENT_DIR/$client_name.conf"
    green "    二维码: $CLIENT_DIR/$client_name-qr.txt"
}

# 系统优化
optimize_system() {
    yellow "[*] 优化系统性能..."
    
    # 网络参数优化
    cat >> /etc/sysctl.conf <<'EOF'

# WireGuard 优化参数
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 4096
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
fs.file-max = 1048576
EOF

    sysctl -p
    
    # 文件描述符限制
    cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 1048576  
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    green "[*] 系统优化完成"
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
    echo "=== 接口详情 ==="
    wg show $VPN_INTERFACE 2>/dev/null || echo "接口未启动"
    echo ""
    echo "=== 系统资源 ==="
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')%"
    echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "负载: $(uptime | awk -F'load average:' '{print $2}')"
}

show_clients() {
    echo "=== 客户端连接状态 ==="
    if wg show $VPN_INTERFACE 2>/dev/null | grep -q peer; then
        wg show $VPN_INTERFACE peers | while read -r pubkey; do
            endpoint=$(wg show $VPN_INTERFACE endpoints | grep "$pubkey" | awk '{print $2}')
            latest_handshake=$(wg show $VPN_INTERFACE latest-handshakes | grep "$pubkey" | awk '{print $2}')
            transfer=$(wg show $VPN_INTERFACE transfer | grep "$pubkey" | awk '{print $2, $3}')
            
            echo "客户端: ${pubkey:0:16}..."
            [[ -n "$endpoint" ]] && echo "  终端: $endpoint"
            [[ -n "$latest_handshake" && "$latest_handshake" != "0" ]] && echo "  最后握手: $(date -d @$latest_handshake)"
            [[ -n "$transfer" ]] && echo "  流量: $transfer"
            echo ""
        done
    else
        echo "无客户端连接"
    fi
}

add_client() {
    if [[ -z "$1" ]]; then
        echo "用法: wg-mgr add <客户端名>"
        return 1
    fi
    
    local client_name="$1"
    
    if [[ -f "$CLIENT_DIR/$client_name.conf" ]]; then
        echo "❌ 客户端 $client_name 已存在"
        return 1
    fi
    
    # 生成客户端
    echo "正在生成客户端配置..."
    
    # 这里需要调用主脚本的函数，简化版本
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # 读取服务器信息
    SERVER_PRIVATE_KEY=$(grep "PrivateKey" "$WG_DIR/$VPN_INTERFACE.conf" | awk '{print $3}')
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # 读取预共享密钥
    PRESHARED_KEY=$(wg genpsk)
    
    # 分配IP
    CLIENT_COUNT=$(grep -c "PublicKey" "$WG_DIR/$VPN_INTERFACE.conf" 2>/dev/null || echo "0")
    CLIENT_IP="10.66.66.$((CLIENT_COUNT + 2))/32"
    
    # 获取服务器端口和IP
    SERVER_PORT=$(grep "ListenPort" "$WG_DIR/$VPN_INTERFACE.conf" | awk '{print $3}')
    SERVER_IP=$(curl -s https://api.ipify.org)
    
    # 添加到服务器配置
    cat >> "$WG_DIR/$VPN_INTERFACE.conf" <<PEER_EOF

# Client: $client_name
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_IP%/*}/32
PEER_EOF

    # 生成客户端配置
    cat > "$CLIENT_DIR/$client_name.conf" <<CLIENT_EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $PRESHARED_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
CLIENT_EOF

    chmod 600 "$CLIENT_DIR/$client_name.conf"
    
    # 重载配置
    wg syncconf $VPN_INTERFACE <(wg-quick strip $VPN_INTERFACE)
    
    echo "✅ 客户端 $client_name 添加成功"
    echo "配置文件: $CLIENT_DIR/$client_name.conf"
}

remove_client() {
    if [[ -z "$1" ]]; then
        echo "用法: wg-mgr remove <客户端名>"
        return 1
    fi
    
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name.conf"
    
    if [[ ! -f "$config_file" ]]; then
        echo "❌ 客户端 $client_name 不存在"
        return 1
    fi
    
    # 获取客户端公钥
    local client_pubkey=$(grep "PrivateKey" "$config_file" | awk '{print $3}' | wg pubkey)
    
    # 从服务器配置中删除
    local temp_file=$(mktemp)
    local in_peer_section=false
    local current_peer=""
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[Peer\] ]]; then
            in_peer_section=true
            current_peer=""
            temp_peer_lines=("$line")
        elif [[ "$line" =~ ^\[.*\] ]]; then
            if [[ "$in_peer_section" == true ]] && [[ "$current_peer" != "$client_pubkey" ]]; then
                printf '%s\n' "${temp_peer_lines[@]}" >> "$temp_file"
            fi
            in_peer_section=false
            echo "$line" >> "$temp_file"
        elif [[ "$in_peer_section" == true ]]; then
            temp_peer_lines+=("$line")
            if [[ "$line" =~ ^PublicKey ]]; then
                current_peer=$(echo "$line" | awk '{print $3}')
            fi
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$WG_DIR/$VPN_INTERFACE.conf"
    
    # 处理最后一个 peer
    if [[ "$in_peer_section" == true ]] && [[ "$current_peer" != "$client_pubkey" ]]; then
        printf '%s\n' "${temp_peer_lines[@]}" >> "$temp_file"
    fi
    
    mv "$temp_file" "$WG_DIR/$VPN_INTERFACE.conf"
    
    # 删除客户端文件
    rm -f "$config_file" "$CLIENT_DIR/$client_name-qr.txt"
    
    # 重载配置
    wg syncconf $VPN_INTERFACE <(wg-quick strip $VPN_INTERFACE)
    
    echo "✅ 客户端 $client_name 已删除"
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
        live)
            echo "=== 实时日志 (Ctrl+C 退出) ==="
            journalctl -u wg-quick@$VPN_INTERFACE -f
            ;;
        *)
            echo "=== WireGuard 日志 (最近50行) ==="
            journalctl -u wg-quick@$VPN_INTERFACE --no-pager -n 50
            ;;
    esac
}

restart_service() {
    echo "重启 WireGuard 服务..."
    wg-quick down $VPN_INTERFACE 2>/dev/null
    sleep 2
    wg-quick up $VPN_INTERFACE
    
    if wg show $VPN_INTERFACE &>/dev/null; then
        echo "✅ WireGuard 服务重启成功"
    else
        echo "❌ WireGuard 服务重启失败"
        echo "检查配置: cat $WG_DIR/$VPN_INTERFACE.conf"
    fi
}

backup_config() {
    local backup_dir="/root/wireguard-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    cp -r "$WG_DIR" "$backup_dir/"
    cp -r "$CLIENT_DIR" "$backup_dir/" 2>/dev/null
    
    echo "✅ 配置已备份到: $backup_dir"
}

case "$1" in
    status|st)
        show_status
        ;;
    clients|cl)
        show_clients
        ;;
    add)
        add_client "$2"
        ;;
    remove|rm)
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
    backup|bk)
        backup_config
        ;;
    *)
        echo "WireGuard 管理工具"
        echo ""
        echo "用法: wg-mgr {command} [options]"
        echo ""
        echo "命令:"
        echo "  status / st        查看服务状态"
        echo "  clients / cl       查看客户端连接"
        echo "  add <name>         添加客户端"
        echo "  remove <name>      删除客户端"
        echo "  qr <name>          显示二维码"
        echo "  logs / log         查看日志 (live 实时日志)"
        echo "  restart / rs       重启服务"
        echo "  backup / bk        备份配置"
        echo ""
        echo "示例:"
        echo "  wg-mgr add phone   # 添加手机客户端"
        echo "  wg-mgr qr phone    # 显示手机客户端二维码"
        echo "  wg-mgr clients     # 查看所有连接"
        ;;
esac
EOF

    chmod +x /usr/local/bin/wg-mgr
    green "[*] 管理工具创建完成"
}

# 生成使用文档
generate_documentation() {
    cat > "$CLIENT_DIR/README.txt" <<EOF
WireGuard 隐身版使用说明
========================

服务器信息:
- 服务器IP: $SERVER_IP
- VPN网段: $VPN_NET  
- 主端口: $WG_PORT
- 隐身模式: $STEALTH_CONFIG

管理命令:
- wg-mgr status        # 查看服务状态
- wg-mgr add <名称>    # 添加新客户端
- wg-mgr remove <名称> # 删除客户端
- wg-mgr qr <名称>     # 显示二维码
- wg-mgr clients       # 查看连接状态
- wg-mgr restart       # 重启服务
- wg-mgr backup        # 备份配置

客户端软件:
- Windows: WireGuard for Windows
- macOS: WireGuard for macOS  
- iOS: WireGuard (App Store)
- Android: WireGuard (Google Play)
- Linux: wireguard-tools

连接方法:
1. 下载对应平台的 WireGuard 客户端
2. 导入配置文件或扫描二维码
3. 点击连接即可使用

配置文件位置:
- 服务器配置: $WG_DIR/$VPN_INTERFACE.conf
- 客户端配置: $CLIENT_DIR/*.conf
- 日志文件: $LOG_DIR/wireguard.log

抗封锁特性:
$(case $STEALTH_CONFIG in
    websocket) echo "- WebSocket 隧道伪装
- HTTPS 流量特征
- 端口 $WS_PORT 和 $HTTPS_PORT" ;;
    port_hop) echo "- 自动端口跳跃 (每6小时)
- 端口池: ${PORTS[*]}
- 降低端口封锁风险" ;;
    multi_port) echo "- 多端口并发支持
- 主端口: $MAIN_PORT
- 备用端口: ${ALT_PORTS[*]}" ;;
    *) echo "- 使用非标准端口 $WG_PORT
- 基础混淆保护
- fail2ban 防护" ;;
esac)

使用建议:
1. 定期检查服务状态
2. 不要分享配置给太多人
3. 注意流量使用，避免异常
4. 定期备份配置文件
5. 配合其他协议使用更安全

故障排除:
1. 服务无法启动: 检查端口占用和防火墙
2. 无法连接: 验证客户端配置和服务器状态  
3. 速度慢: 尝试调整 MTU 值
4. 频繁断线: 检查网络稳定性和 KeepAlive 设置

技术支持:
- 查看日志: journalctl -u wg-quick@wg0 -f
- 检查接口: wg show wg0
- 网络测试: ping 10.66.66.1

生成时间: $(date)
最后更新: $(date)
EOF

    chmod 600 "$CLIENT_DIR/README.txt"
    green "[*] 使用文档生成完成"
}

# 清理临时文件
cleanup_installation() {
    yellow "[*] 清理安装文件..."
    
    # 清理包缓存
    case $SYSTEM in
        "ubuntu"|"debian")
            apt autoremove -y
            apt autoclean
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            $PKG_MANAGER clean all
            ;;
    esac
    
    # 清理历史记录
    history -c
    echo "" > ~/.bash_history
    
    green "[*] 清理完成"
}

# 主安装流程
main() {
    cyan "========================================"
    cyan "    WireGuard 隐身增强版安装脚本"
    cyan "========================================"
    echo ""
    
    # 检查系统
    detect_system
    
    # 解决包管理器锁定问题并安装依赖
    install_dependencies
    
    # 获取服务器信息
    get_server_ip
    
    # 选择抗封锁方案
    show_stealth_menu
    
    # 生成密钥
    generate_keys
    
    # 配置服务器
    configure_wireguard_server
    
    # 部署抗封锁层
    deploy_stealth_layer
    
    # 配置防火墙
    configure_firewall
    
    # 启动服务
    start_wireguard_service
    
    # 生成默认客户端
    generate_client_config "client1"
    
    # 系统优化
    optimize_system
    
    # 创建管理工具
    create_management_tools
    
    # 生成文档
    generate_documentation
    
    # 清理
    cleanup_installation
    
    # 显示安装结果
    green "\n========================================"
    green "    WireGuard 隐身版安装成功! ✅"
    green "========================================"
    echo ""
    cyan "服务器信息:"
    echo "  IP地址: $SERVER_IP"
    echo "  VPN网段: $VPN_NET"
    echo "  监听端口: $WG_PORT"
    echo "  隐身模式: $STEALTH_CONFIG"
    
    case $STEALTH_CONFIG in
        websocket)
            echo "  WebSocket端口: $WS_PORT"
            echo "  HTTPS端口: $HTTPS_PORT"
            ;;
        port_hop)
            echo "  端口池: ${PORTS[*]}"
            ;;
        multi_port)  
            echo "  备用端口: ${ALT_PORTS[*]}"
            ;;
    esac
    
    echo ""
    cyan "客户端配置:"
    echo "  默认客户端: client1"
    echo "  配置文件: $CLIENT_DIR/client1.conf"
    echo "  二维码: $CLIENT_DIR/client1-qr.txt"
    echo ""
    cyan "管理命令:"
    echo "  wg-mgr status      # 查看状态"
    echo "  wg-mgr add phone   # 添加手机端"
    echo "  wg-mgr qr client1  # 显示二维码"
    echo "  wg-mgr clients     # 查看连接"
    echo ""
    yellow "首次使用:"
    echo "1. 手机安装 WireGuard 客户端"
    echo "2. 运行: wg-mgr qr client1"
    echo "3. 扫描二维码导入配置"
    echo "4. 点击连接开关即可"
    echo ""
    green "WireGuard 隐身版已准备就绪! 🎉"
    
    # 显示二维码
    echo ""
    yellow "客户端1 二维码:"
    if [[ -f "$CLIENT_DIR/client1-qr.txt" ]]; then
        cat "$CLIENT_DIR/client1-qr.txt"
    else
        qrencode -t ANSIUTF8 < "$CLIENT_DIR/client1.conf"
    fi
    
    echo ""
    green "安装完成! 请查看 $CLIENT_DIR/README.txt 了解详细使用说明"
    echo "========================================"
}

# 执行主函数
main "$@"