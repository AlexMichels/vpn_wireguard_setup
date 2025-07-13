#!/bin/bash

# Secure WireGuard Setup with DNS Leak Protection
# Author: Alex - Fixed version with complete DNS security

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Secure WireGuard Setup with DNS Protection${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Global variables
WG_DIR="/etc/wireguard"
SERVER_CONF="$WG_DIR/wg0.conf"
CLIENTS_DIR="$WG_DIR/clients"
DNS_LEAK_TEST_SCRIPT="$WG_DIR/test-dns-leak.sh"

# Create directories
mkdir -p "$WG_DIR" "$CLIENTS_DIR"
chmod 700 "$WG_DIR"

# Function to install required packages
install_packages() {
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt update
    apt install -y wireguard wireguard-tools qrencode unbound iptables-persistent
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
}

# Function to setup Unbound DNS resolver
setup_unbound() {
    echo -e "${YELLOW}Setting up Unbound DNS resolver for leak protection...${NC}"
    
    # Configure Unbound
    cat > /etc/unbound/unbound.conf.d/wireguard.conf << 'EOF'
server:
    interface: 0.0.0.0
    interface: ::0
    access-control: 10.0.0.0/24 allow
    access-control: 127.0.0.0/8 allow
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # Privacy options
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    
    # Security
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    
    # Use Cloudflare DNS over TLS
    forward-zone:
        name: "."
        forward-tls-upstream: yes
        forward-addr: 1.1.1.1@853
        forward-addr: 1.0.0.1@853
EOF
    
    # Restart Unbound
    systemctl restart unbound
    systemctl enable unbound
}

# Function to create secure iptables rules
setup_firewall() {
    echo -e "${YELLOW}Setting up firewall rules for DNS leak protection...${NC}"
    
    # Get default interface
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}')
    
    # Create comprehensive iptables rules
    cat > /etc/iptables/rules.v4 << EOF
*filter
# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow WireGuard
-A INPUT -p udp --dport 51820 -j ACCEPT

# Allow SSH (adjust port if needed)
-A INPUT -p tcp --dport 22 -j ACCEPT

# DNS leak protection - Force all DNS through tunnel
-A OUTPUT -p udp --dport 53 -m owner --uid-owner unbound -j ACCEPT
-A OUTPUT -p tcp --dport 53 -m owner --uid-owner unbound -j ACCEPT
-A OUTPUT -p udp --dport 53 -j DROP
-A OUTPUT -p tcp --dport 53 -j DROP

# Drop all other input
-A INPUT -j DROP

COMMIT

*nat
# NAT for WireGuard clients
-A POSTROUTING -s 10.0.0.0/24 -o $DEFAULT_IFACE -j MASQUERADE

# DNS hijacking - redirect all DNS to local Unbound
-A PREROUTING -s 10.0.0.0/24 -p udp --dport 53 -j DNAT --to-destination 10.0.0.1:53
-A PREROUTING -s 10.0.0.0/24 -p tcp --dport 53 -j DNAT --to-destination 10.0.0.1:53

COMMIT
EOF
    
    # Apply rules
    iptables-restore < /etc/iptables/rules.v4
}

# Function to generate server config
generate_server_config() {
    echo -e "${YELLOW}Generating server configuration...${NC}"
    
    # Generate server keys
    SERVER_PRIV=$(wg genkey)
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    
    # Get public IP
    PUBLIC_IP=$(curl -s -4 https://ifconfig.me)
    
    # Create server config
    cat > "$SERVER_CONF" << EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV

# DNS Leak Protection Rules
PostUp = iptables-restore < /etc/iptables/rules.v4
PostUp = ip6tables-restore < /etc/iptables/rules.v6
PostDown = iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X
PostDown = ip6tables -F; ip6tables -X; ip6tables -t nat -F; ip6tables -t nat -X

# Save server public key
# PublicKey = $SERVER_PUB
EOF
    
    echo "$SERVER_PUB" > "$WG_DIR/server-public.key"
    echo -e "${GREEN}Server configuration created!${NC}"
}

# Function to create secure client
create_secure_client() {
    read -p "Enter client name: " CLIENT_NAME
    
    if [ -f "$CLIENTS_DIR/$CLIENT_NAME.conf" ]; then
        echo -e "${RED}Client already exists!${NC}"
        return
    fi
    
    # Find next available IP
    LAST_IP=$(grep -h "AllowedIPs" "$SERVER_CONF" 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
    if [ -z "$LAST_IP" ]; then
        CLIENT_IP="10.0.0.2"
    else
        LAST_OCTET=$(echo "$LAST_IP" | cut -d. -f4)
        CLIENT_IP="10.0.0.$((LAST_OCTET + 1))"
    fi
    
    # Generate client keys
    CLIENT_PRIV=$(wg genkey)
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    PSK=$(wg genpsk)
    
    # Get server public key
    SERVER_PUB=$(cat "$WG_DIR/server-public.key")
    PUBLIC_IP=$(curl -s -4 https://ifconfig.me)
    
    # Create client config with maximum security
    cat > "$CLIENTS_DIR/$CLIENT_NAME.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = $CLIENT_IP/32
DNS = 10.0.0.1
# DNS Leak Protection on Client
PostUp = iptables -A OUTPUT -d 10.0.0.0/24 -j ACCEPT; iptables -A OUTPUT -p udp --dport 53 -j DROP; iptables -A OUTPUT -p tcp --dport 53 -j DROP
PostDown = iptables -D OUTPUT -d 10.0.0.0/24 -j ACCEPT; iptables -D OUTPUT -p udp --dport 53 -j DROP; iptables -D OUTPUT -p tcp --dport 53 -j DROP

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PSK
Endpoint = $PUBLIC_IP:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # Add peer to server
    cat >> "$SERVER_CONF" << EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PSK
AllowedIPs = $CLIENT_IP/32
EOF
    
    # Reload WireGuard
    wg syncconf wg0 <(wg-quick strip wg0)
    
    echo -e "${GREEN}Client $CLIENT_NAME created with IP $CLIENT_IP${NC}"
    echo -e "${YELLOW}Client configuration saved to: $CLIENTS_DIR/$CLIENT_NAME.conf${NC}"
    
    # Generate QR code
    echo -e "${YELLOW}QR Code for mobile clients:${NC}"
    qrencode -t ansiutf8 < "$CLIENTS_DIR/$CLIENT_NAME.conf"
}

# Create DNS leak test script
create_dns_test() {
    cat > "$DNS_LEAK_TEST_SCRIPT" << 'EOF'
#!/bin/bash
echo "Testing for DNS leaks..."
echo "Your DNS servers should only show your VPN provider:"
echo ""
curl -s https://api.dnsleaktest.com/test/$(curl -s https://api.dnsleaktest.com/test/ | jq -r '.test_id')?limit=10 | jq -r '.[] | "\(.ip) - \(.hostname) - \(.isp) - \(.country)"'
EOF
    chmod +x "$DNS_LEAK_TEST_SCRIPT"
}

# Main menu
main_menu() {
    while true; do
        echo -e "\n${GREEN}=== Secure WireGuard Management ===${NC}"
        echo "1. Initial setup (fresh install)"
        echo "2. Add new client"
        echo "3. Show WireGuard status"
        echo "4. Test for DNS leaks"
        echo "5. Exit"
        
        read -p "Select option: " choice
        
        case $choice in
            1)
                install_packages
                setup_unbound
                setup_firewall
                generate_server_config
                create_dns_test
                
                # Start WireGuard
                systemctl enable wg-quick@wg0
                systemctl start wg-quick@wg0
                
                echo -e "${GREEN}Setup complete! WireGuard is running with DNS leak protection.${NC}"
                ;;
            2)
                create_secure_client
                ;;
            3)
                wg show
                ;;
            4)
                if [ -f "$DNS_LEAK_TEST_SCRIPT" ]; then
                    bash "$DNS_LEAK_TEST_SCRIPT"
                else
                    echo -e "${RED}Test script not found. Run initial setup first.${NC}"
                fi
                ;;
            5)
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
}

# Run main menu
main_menu 