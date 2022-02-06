#!/bin/bash
# v2ray one-click installation script
# Author: hijk<https://hijk.art>


RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

# The following website is an ad-free novel website randomly found on Google. If you don't like it, please change it to another URL, starting with http or https
# The fake domain name cannot be opened after it is set up. It may be that the anti-generation novel website is down. Please leave a message on the website or issue an issue on Github to replace the new website.
SITES=(
http://www.zhuizishu.com/
http://xs.56dyc.com/
#http://www.xiaoshuosk.com/
#https://www.quledu.net/
http://www.ddxsku.com/
http://www.biqu6.com/
https://www.wenshulou.cc/
#http://www.auutea.com/
http://www.55shuba.com/
http://www.39shubao.com/
https://www.23xsw.cc/
https://www.huanbige.com/
https://www.jueshitangmen.info/
https://www.zhetian.org/
http://www.bequgexs.com/
http://www.tjwl.com/
)

CONFIG_FILE="/etc/v2ray/config.json"
SERVICE_FILE="/etc/systemd/system/v2ray.service"
OS=`hostnamectl | grep -i system | cut -d: -f2`

V6_PROXY=""
IP=`curl -sL -4 ip.sb`
if [[ "$?" != "0" ]]; then
    IP=`curl -sL -6 ip.sb`
    V6_PROXY="https://gh.hijk.art/"
be

BT="false"
NGINX_CONF_PATH="/etc/nginx/conf.d/"
res=`which bt 2>/dev/null`
if [[ "$res" != "" ]]; then
    BT="true"
    NGINX_CONF_PATH="/www/server/panel/vhost/nginx/"
be

VLESS="false"
TROJAN="false"
TLS="false"
WS="false"
XTLS="false"
KCP="false"

checkSystem() {
    result=$(id | awk '{print $1}')
    if [[ $result != "uid=0(root)" ]]; then
        colorEcho $RED "Please execute this script as root"
        exit 1
    be

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED "Unsupported Linux system"
            exit 1
        be
        PMT="apt"
        CMD_INSTALL="apt install -y "
        CMD_REMOVE="apt remove -y "
        CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"
    else
        PMT="yum"
        CMD_INSTALL="yum install -y "
        CMD_REMOVE="yum remove -y "
        CMD_UPGRADE="yum update -y"
    be
    res=`which systemctl 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        colorEcho $RED "The system version is too low, please upgrade to the latest version"
        exit 1
    be
}

colorEcho() {
    echo -e "${1}${@:2}${PLAIN}"
}

configNeedNginx() {
    local ws=`grep wsSettings $CONFIG_FILE`
    if [[ -z "$ws" ]]; then
        echo no
        return
    be
    echo yes
}

needNginx() {
    if [[ "$WS" = "false" ]]; then
        echo no
        return
    be
    echo yes
}

status() {
    if [[ ! -f /usr/bin/v2ray/v2ray ]]; then
        echo 0
        return
    be
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    be
    port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`
    res=`ss -nutlp| grep ${port} | grep -i v2ray`
    if [[ -z "$res" ]]; then
        echo 2
        return
    be

    if [[ `configNeedNginx` != "yes" ]]; then
        echo 3
    else
        res=`ss -nutlp|grep -i nginx`
        if [[ -z "$res" ]]; then
            echo 4
        else
            echo 5
        be
    be
}

statusText() {
    res=`status`
    case $res in
        2)
            echo -e ${GREEN}installed${PLAIN} ${RED}not running${PLAIN}
            ;;
        3)
            echo -e ${GREEN}Installed${PLAIN} ${GREEN}V2ray is running${PLAIN}
            ;;
        4)
            echo -e ${GREEN}Installed${PLAIN} ${GREEN}V2ray is running${PLAIN}, ${RED}Nginx is not running${PLAIN}
            ;;
        5)
            echo -e ${GREEN}Installed${PLAIN} ${GREEN}V2ray is running, Nginx is running ${PLAIN}
            ;;
        *)
            echo -e ${RED}${PLAIN} is not installed
            ;;
    esac
}

normalizeVersion() {
    if [ -n "$1" ]; then
        case "$1" in
            v*)
                echo "$1"
            ;;
            *)
                echo "v$1"
            ;;
        esac
    else
        echo ""
    be
}

# 1: new V2Ray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
    VER="$(/usr/bin/v2ray/v2ray -version 2>/dev/null)"
    RETVAL=$?
    CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
    TAG_URL="${V6_PROXY}https://api.github.com/repos/v2fly/v2ray-core/releases/latest"
    NEW_VER="$(normalizeVersion "$(curl -s "${TAG_URL}" --connect-timeout 10| tr ',' '\n' | grep 'tag_name' | cut -d\" -f4)")"
    if [[ "$XTLS" = "true" ]]; then
        NEW_VER=v4.32.1
    be

    if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
        colorEcho $RED "Failed to check V2ray version information, please check the network"
        return 3
    elif [[ $RETVAL -ne 0 ]];then
        return 2
    elif [[ $NEW_VER != $CUR_VER ]];then
        return 1
    be
    return 0
}

archAffix () {
    case "$(uname -m)" in
        i686|i386)
            echo '32'
        ;;
        x86_64|amd64)
            echo '64'
        ;;
        *armv7*)
            echo 'arm32-v7a'
            ;;
        armv6*)
            echo 'arm32-v6a'
        ;;
        *armv8*|aarch64)
            echo 'arm64-v8a'
        ;;
        *mips64le*)
            echo 'mips64le'
        ;;
        *mips64*)
            echo 'mips64'
        ;;
        *mipsle*)
            echo 'mipsle'
        ;;
        *mips*)
            echo 'mips'
        ;;
        *s390x*)
            echo 's390x'
        ;;
        ppc64le)
            echo 'ppc64le'
        ;;
        ppc64)
            echo 'ppc64'
        ;;
        *)
            colorEcho $RED "Unsupported CPU architecture!"
            exit 1
        ;;
    esac

	return 0
}

getData() {
    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        echo ""
        echo "V2ray one-click script, please make sure the following conditions are met before running:"
        colorEcho ${YELLOW} "1. A fake domain name"
        colorEcho ${YELLOW} " 2. Fake domain name DNS resolution to point to the current server ip (${IP})"
        colorEcho ${BLUE} " 3. If there are v2ray.pem and v2ray.key certificate key files in the /root directory, disregard condition 2"
        echo " "
        read -p " Press y to confirm, press other to exit the script:" answer
        if [[ "${answer,,}" != "y" ]]; then
            exit 0
        be

        echo ""
        while true
        do
            read -p "Please enter fake domain name:" DOMAIN
            if [[ -z "${DOMAIN}" ]]; then
                colorEcho ${RED} "The domain name was entered incorrectly, please try again!"
            else
                break
            be
        done
        DOMAIN=${DOMAIN,,}
        colorEcho ${BLUE} "Fake domain name (host): $DOMAIN"

        if [[ -f ~/v2ray.pem && -f ~/v2ray.key ]]; then
            colorEcho ${BLUE} "Own certificate detected and will be deployed using it"
            CERT_FILE="/etc/v2ray/${DOMAIN}.pem"
            KEY_FILE="/etc/v2ray/${DOMAIN}.key"
        else
            resolve=`curl -sL https://hijk.art/hostip.php?d=${DOMAIN}`
            res=`echo -n ${resolve} | grep ${IP}`
            if [[ -z "${res}" ]]; then
                colorEcho ${BLUE} "${DOMAIN} resolve result: ${resolve}"
                colorEcho ${RED} "The domain name is not resolved to the current server IP (${IP})!"
                exit 1
            be
        be
    be

    echo ""
    if [[ "$(needNginx)" = "no" ]]; then
        if [[ "$TLS" = "true" ]]; then
            read -p "Please enter the v2ray listening port [strongly recommended 443, default 443]:" PORT
            [[ -z "${PORT}" ]] && PORT=443
        else
            read -p "Please enter the v2ray listening port [a number from 100-65535]:" PORT
            [[ -z "${PORT}" ]] && PORT=`shuf -i200-65000 -n1`
            if [[ "${PORT:0:1}" = "0" ]]; then
                colorEcho ${RED} "Port cannot start with 0"
                exit 1
            be
        be
        colorEcho ${BLUE} "v2ray port: $PORT"
    else
        read -p "Please enter a number of Nginx listening port [100-65535, default 443]:" PORT
        [[ -z "${PORT}" ]] && PORT=443
        if [ "${PORT:0:1}" = "0" ]; then
            colorEcho ${BLUE} "Port cannot start with 0"
            exit 1
        be
        colorEcho ${BLUE} "Nginx port: $PORT"
        V2PORT=`shuf -i10000-65000 -n1`
    be

    if [[ "$KCP" = "true" ]]; then
        echo ""
        colorEcho $BLUE "Please select a camouflage type:"
        echo "1) None"
        echo " 2) BT download"
        echo " 3) Video call"
        echo " 4) WeChat video call"
        echo "   5) dtls"
        echo "   6) wiregard"
        read -p "Please choose a masquerade type [default: none]:" answer
        case $answer in
            2)
                HEADER_TYPE="utp"
                ;;
            3)
                HEADER_TYPE="srtp"
                ;;
            4)
                HEADER_TYPE="wechat-video"
                ;;
            5)
                HEADER_TYPE="dtls"
                ;;
            6)
                HEADER_TYPE="wireguard"
                ;;
            *)
                HEADER_TYPE="none"
                ;;
        esac
        colorEcho $BLUE "Fake Type: $HEADER_TYPE"
        SEED=`cat /proc/sys/kernel/random/uuid`
    be

    if [[ "$TROJAN" = "true" ]]; then
        echo ""
        read -p "Please set the trojan password (if you don't enter it, it will be randomly generated):" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
        colorEcho $BLUE "trojan password: $PASSWORD"
    be

    if [[ "$XTLS" = "true" ]]; then
        echo ""
        colorEcho $BLUE "Please select a flow control mode:"
        echo -e "1) xtls-rprx-direct [$RED recommends $PLAIN]"
        echo "   2) xtls-rprx-origin"
        read -p "Please select flow control mode [default: direct]" answer
        [[ -z "$answer" ]] && answer=1
        case $answer in
            1)
                FLOW="xtls-rprx-direct"
                ;;
            2)
                FLOW="xtls-rprx-origin"
                ;;
            *)
                colorEcho $RED "Invalid option, use default xtls-rprx-direct"
                FLOW="xtls-rprx-direct"
                ;;
        esac
        colorEcho $BLUE "Flow control mode: $FLOW"
    be

    if [[ "${WS}" = "true" ]]; then
        echo ""
        while true
        do
            read -p "Please enter the disguised path, starting with / (please press Enter if you don't understand):" WSPATH
            if [[ -z "${WSPATH}" ]]; then
                len=`shuf -i5-12 -n1`
                ws=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $len | head -n 1`
                WSPATH="/$ws"
                break
            elif [[ "${WSPATH:0:1}" != "/" ]]; then
                colorEcho ${RED} "The masquerading path must start with /!"
            elif [[ "${WSPATH}" = "/" ]]; then
                colorEcho ${RED} "Cannot use root path!"
            else
                break
            be
        done
        colorEcho ${BLUE}  " ws路径：$WSPATH"
    be

    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        echo ""
        colorEcho $BLUE "Please select a camouflage station type:"
        echo "1) Static website (located in /usr/share/nginx/html)"
        echo " 2) Novel Station (randomly selected)"
        echo " 3) Beauty Station (https://imeizi.me)"
        echo " 4) HD Wallpaper Site (https://bing.imeizi.me)"
        echo "5) Customize the reverse generation site (need to start with http or https)"
        read -p "Please select a fake site type [default: HD wallpaper]" answer
        if [[ -z "$answer" ]]; then
            PROXY_URL="https://bing.imeizi.me"
        else
            case $answer in
            1)
                PROXY_URL=""
                ;;
            2)
                len=${#SITES[@]}
                ((len--))
                while true
                do
                    index=`shuf -i0-${len} -n1`
                    PROXY_URL=${SITES[$index]}
                    host=`echo ${PROXY_URL} | cut -d/ -f3`
                    ip=`curl -sL https://hijk.art/hostip.php?d=${host}`
                    res=`echo -n ${ip} | grep ${host}`
                    if [[ "${res}" = "" ]]; then
                        echo "$ip $host" >> /etc/hosts
                        break
                    be
                done
                ;;
            3)
                PROXY_URL="https://imeizi.me"
                ;;
            4)
                PROXY_URL="https://bing.imeizi.me"
                ;;
            5)
                read -p "Please enter the reverse site (starting with http or https):" PROXY_URL
                if [[ -z "$PROXY_URL" ]]; then
                    colorEcho $RED "Please enter the anti-generation website!"
                    exit 1
                elif [[ "${PROXY_URL:0:4}" != "http" ]]; then
                    colorEcho $RED "Reverse site must start with http or https!"
                    exit 1
                be
                ;;
            *)
                colorEcho $RED "Please enter the correct option!"
                exit 1
            esac
        be
        REMOTE_HOST=`echo ${PROXY_URL} | cut -d/ -f3`
        colorEcho $BLUE "Fake website: $PROXY_URL"

        echo ""
        colorEcho $BLUE "Allow search engines to crawl the site? [default: not allowed]"
        echo "y) Allowed, there will be more ip requests to the website, but some traffic will be consumed, it is recommended to use when the vps traffic is sufficient"
        echo "n) is not allowed, the crawler will not access the website, the access ip is relatively simple, but it can save vps traffic"
        read -p "Please select: [y/n]" answer
        if [[ -z "$answer" ]]; then
            ALLOW_SPIDER="n"
        elif [[ "${answer,,}" = "y" ]]; then
            ALLOW_SPIDER="y"
        else
            ALLOW_SPIDER="n"
        be
        colorEcho $BLUE "Allow search engines: $ALLOW_SPIDER"
    be

    echo ""
    read -p "Do you want to install BBR (default)? [y/n]:" NEED_BBR
    [[ -z "$NEED_BBR" ]] && NEED_BBR=y
    [[ "$NEED_BBR" = "Y" ]] && NEED_BBR=y
    colorEcho $BLUE " 安装BBR：$NEED_BBR"
}

installNginx() {
    echo ""
    colorEcho $BLUE "Install nginx..."
    if [[ "$BT" = "false" ]]; then
        if [[ "$PMT" = "yum" ]]; then
            $CMD_INSTALL epel-release
            if [[ "$?" != "0" ]]; then
                echo '[nginx-stable]
name=nginx stable repo
baseurl = http: //nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true' > /etc/yum.repos.d/nginx.repo
            be
        be
        $CMD_INSTALL nginx
        if [[ "$?" != "0" ]]; then
            colorEcho $RED "Nginx installation failed, please go to https://hijk.art for feedback"
            exit 1
        be
        systemctl enable nginx
    else
        res=`which nginx 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorEcho $RED "You have installed the pagoda, please install nginx in the background of the pagoda before running this script"
            exit 1
        be
    be
}

startNginx () {
    if [[ "$BT" = "false" ]]; then
        systemctl start nginx
    else
        nginx -c /www/server/nginx/conf/nginx.conf
    be
}

stopNginx() {
    if [[ "$BT" = "false" ]]; then
        systemctl stop nginx
    else
        res = `ps aux | grep -i nginx`
        if [[ "$res" != "" ]]; then
            nginx -s stop
        be
    be
}

getCert () {
    mkdir -p /etc/v2ray
    if [[ -z ${CERT_FILE+x} ]]; then
        stopNginx
        sleep 2
        res = `netstat -ntlp | grep -E ': 80 |: 443' `
        if [[ "${res}" != "" ]]; then
            colorEcho ${RED} "Other process occupies port 80 or 443, please close it first and then run the one-click script"
            echo "The port occupancy information is as follows:"
            echo ${res}
            exit 1
        be

        $CMD_INSTALL socat openssl
        if [[ "$PMT" = "yum" ]]; then
            $CMD_INSTALL cronie
            systemctl start crond
            systemctl enable crond
        else
            $CMD_INSTALL cron
            systemctl start cron
            systemctl enable cron
        be
        curl -sL https://get.acme.sh | sh -s email=hijk.pw@protonmail.ch
        source ~/.bashrc
        ~/.acme.sh/acme.sh  --upgrade  --auto-upgrade
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        if [[ "$BT" = "false" ]]; then
            ~/.acme.sh/acme.sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx"  --standalone
        else
            ~/.acme.sh/acme.sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "nginx -s stop || { echo -n ''; }" --post-hook "nginx -c /www/server/nginx/conf/nginx.conf || { echo -n ''; }"  --standalone
        be
        [[ -f ~/.acme.sh/${DOMAIN}_ecc/ca.cer ]] || {
            colorEcho $RED "Failed to get the certificate, please copy the red text above to https://hijk.art Feedback"
            exit 1
        }
        CERT_FILE="/etc/v2ray/${DOMAIN}.pem"
        KEY_FILE="/etc/v2ray/${DOMAIN}.key"
        ~/.acme.sh/acme.sh  --install-cert -d $DOMAIN --ecc \
            --key-file       $KEY_FILE  \
            --fullchain-file $CERT_FILE \
            --reloadcmd     "service nginx force-reload"
        [[ -f $CERT_FILE && -f $KEY_FILE ]] || {
            colorEcho $RED "Failed to get certificate, please go to https://hijk.art for feedback"
            exit 1
        }
    else
        cp ~/v2ray.pem /etc/v2ray/${DOMAIN}.pem
        cp ~/v2ray.key /etc/v2ray/${DOMAIN}.key
    be
}

configNginx() {
    mkdir -p /usr/share/nginx/html;
    if [[ "$ALLOW_SPIDER" = "n" ]]; then
        echo 'User-Agent: *' > /usr/share/nginx/html/robots.txt
        echo 'Disallow: /' >> /usr/share/nginx/html/robots.txt
        ROBOT_CONFIG="    location = /robots.txt {}"
    else
        ROBOT_CONFIG=""
    be

    if [[ "$BT" = "false" ]]; then
        if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
            mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        be
        res=`id nginx 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            user="www-data"
        else
            user="nginx"
        be
        cat > /etc/nginx/nginx.conf<<-EOF
user $user;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    server_tokens off;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
    gzip                on;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}
EOF
    be

    if [[ "$PROXY_URL" = "" ]]; then
        action=""
    else
        action="proxy_ssl_server_name on;
        proxy_pass $PROXY_URL;
        proxy_set_header Accept-Encoding '';
        sub_filter \"$REMOTE_HOST\" \"$DOMAIN\";
        sub_filter_once off;"
    be

    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        mkdir -p $NGINX_CONF_PATH
        # VMESS + WS + TLS
        # VLESS+WS+TLS
        if [[ "$WS" = "true" ]]; then
            cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$server_name:${PORT}\$request_uri;
}

server {
    listen       ${PORT} ssl http2;
    listen       [::]:${PORT} ssl http2;
    server_name ${DOMAIN};
    charset utf-8;

    # ssl configuration
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256: ECDHE: ECDH: AES: HIGH:! NULL:! aNULL:! MD5:! ADH:! RC4;
    ssl_ecdh_curve secp384r1;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;

    root /usr/share/nginx/html;
    location / {
        $action
    }
    $ROBOT_CONFIG

    location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:${V2PORT};
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      # Show real IP in v2ray access.log
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
        else
            # VLESS+TCP+TLS
            # VLESS+TCP+XTLS
            # trojan
            cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    listen 81 http2;
    server_name ${DOMAIN};
    root /usr/share/nginx/html;
    location / {
        $action
    }
    $ROBOT_CONFIG
}
EOF
        be
    be
}

setSelinux () {
    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    be
}

setFirewall() {
    res=`which firewall-cmd 2>/dev/null`
    if [[ $? -eq 0 ]]; then
        systemctl status firewalld > /dev/null 2>&1
        if [[ $? -eq 0 ]];then
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            if [[ "$PORT" != "443" ]]; then
                firewall-cmd --permanent --add-port=${PORT}/tcp
                firewall-cmd --permanent --add-port=${PORT}/udp
            be
            firewall-cmd --reload
        else
            nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
            if [[ "$nl" != "3" ]]; then
                iptables -I INPUT -p tcp --dport 80 -j ACCEPT
                iptables -I INPUT -p tcp --dport 443 -j ACCEPT
                if [[ "$PORT" != "443" ]]; then
                    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
                    iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
                be
            be
        be
    else
        res=`which iptables 2>/dev/null`
        if [[ $? -eq 0 ]]; then
            nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
            if [[ "$nl" != "3" ]]; then
                iptables -I INPUT -p tcp --dport 80 -j ACCEPT
                iptables -I INPUT -p tcp --dport 443 -j ACCEPT
                if [[ "$PORT" != "443" ]]; then
                    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
                    iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
                be
            be
        else
            res=`which ufw 2>/dev/null`
            if [[ $? -eq 0 ]]; then
                res=`ufw status | grep -i inactive`
                if [[ "$res" = "" ]]; then
                    ufw allow http/tcp
                    ufw allow https/tcp
                    if [[ "$PORT" != "443" ]]; then
                        ufw allow ${PORT}/tcp
                        ufw allow ${PORT}/udp
                    be
                be
            be
        be
    be
}

installBBR() {
    if [[ "$NEED_BBR" != "y" ]]; then
        INSTALL_BBR=false
        return
    be
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        colorEcho $BLUE "BBR module installed"
        INSTALL_BBR=false
        return
    be
    res=`hostnamectl | grep -i openvz`
    if [[ "$res" != "" ]]; then
        colorEcho $BLUE "openvz machine, skip install"
        INSTALL_BBR=false
        return
    be
    
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        colorEcho $GREEN "BBR module enabled"
        INSTALL_BBR=false
        return
    be

    colorEcho $BLUE "Install BBR module..."
    if [[ "$PMT" = "yum" ]]; then
        if [[ "$V6_PROXY" = "" ]]; then
            rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
            rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
            $CMD_INSTALL --enablerepo=elrepo-kernel kernel-ml
            $CMD_REMOVE kernel-3.*
            grub2-set-default 0
            echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
            INSTALL_BBR=true
        be
    else
        $CMD_INSTALL --install-recommends linux-generic-hwe-16.04
        grub-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
        INSTALL_BBR=true
    be
}

installV2ray() {
    rm -rf /tmp/v2ray
    mkdir -p /tmp/v2ray
    DOWNLOAD_LINK="${V6_PROXY}https://github.com/v2fly/v2ray-core/releases/download/${NEW_VER}/v2ray-linux-$(archAffix).zip"
    colorEcho $BLUE " 下载V2Ray: ${DOWNLOAD_LINK}"
    curl -L -H "Cache-Control: no-cache" -o /tmp/v2ray/v2ray.zip ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        colorEcho $RED "Failed to download V2ray file, please check server network settings"
        exit 1
    be
    mkdir -p '/etc/v2ray' '/var/log/v2ray' && \
    unzip /tmp/v2ray/v2ray.zip -d /tmp/v2ray
    mkdir -p /usr/bin/v2ray
    cp /tmp/v2ray/v2ctl /usr/bin/v2ray/; cp /tmp/v2ray/v2ray /usr/bin/v2ray/; cp /tmp/v2ray/geo* /usr/bin/v2ray/;
    chmod +x '/usr/bin/v2ray/v2ray' '/usr/bin/v2ray/v2ctl' || {
        colorEcho $RED "V2ray installation failed"
        exit 1
    }

    cat >$SERVICE_FILE<<-EOF
[Unit]
Description=V2ray Service
Documentation=https://hijk.art
After=network.target nss-lookup.target

[Service]
# If the version of systemd is 240 or above, then uncommenting Type=exec and commenting out Type=simple
#Type=exec
Type=simple
# This service runs as root. You may consider to run it as another user for security concerns.
# By uncommenting User=nobody and commenting out User=root, the service will run as user nobody.
# More discussion at https://github.com/v2ray/v2ray-core/issues/1011
User=root
#User=nobody
NoNewPrivileges=true
ExecStart=/usr/bin/v2ray/v2ray -config /etc/v2ray/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable v2ray.service
}

trojanConfig() {
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [
        {
          "password": "$PASSWORD"
        }
      ],
      "fallbacks": [
        {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

trojanXTLSConfig() {
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [
        {
          "password": "$PASSWORD",
          "flow": "$FLOW"
        }
      ],
      "fallbacks": [
          {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vmessConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    local alterid=`shuf -i50-80 -n1`
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": $alterid
        }
      ]
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vmessKCPConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    local alterid=`shuf -i50-80 -n1`
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": $alterid
        }
      ]
    },
    "streamSettings": {
        "network": "mkcp",
        "kcpSettings": {
            "uplinkCapacity": 100,
            "downlinkCapacity": 100,
            "congestion": true,
            "header": {
                "type": "$HEADER_TYPE"
            },
            "seed": "$SEED"
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vmessTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vmessWSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $V2PORT,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
        "network": "ws",
        "wsSettings": {
            "path": "$WSPATH",
            "headers": {
                "Host": "$DOMAIN"
            }
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 0
        }
      ],
      "decryption": "none",
      "fallbacks": [
          {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessXTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "flow": "$FLOW",
          "level": 0
        }
      ],
      "decryption": "none",
      "fallbacks": [
          {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessWSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $V2PORT,
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": {
        "clients": [
            {
                "id": "$uuid",
                "level": 0
            }
        ],
        "decryption": "none"
    },
    "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
            "path": "$WSPATH",
            "headers": {
                "Host": "$DOMAIN"
            }
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

vlessKCPConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 0
        }
      ],
      "decryption": "none"
    },
    "streamSettings": {
        "streamSettings": {
            "network": "mkcp",
            "kcpSettings": {
                "uplinkCapacity": 100,
                "downlinkCapacity": 100,
                "congestion": true,
                "header": {
                    "type": "$HEADER_TYPE"
                },
                "seed": "$SEED"
            }
        }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }]
}
EOF
}

configV2ray() {
    mkdir -p /etc/v2ray
    if [[ "$TROJAN" = "true" ]]; then
        if [[ "$XTLS" = "true" ]]; then
            trojanXTLSConfig
        else
            trojanConfig
        be
        return 0
    be
    if [[ "$VLESS" = "false" ]]; then
        # VMESS + kcp
        if [[ "$KCP" = "true" ]]; then
            vmessKCPConfig
            return 0
        be
        # VMESS
        if [[ "$TLS" = "false" ]]; then
            vmessConfig
        elif [[ "$WS" = "false" ]]; then
            # VMESS+TCP+TLS
            vmessTLSConfig
        # VMESS + WS + TLS
        else
            vmessWSConfig
        be
    #VLESS
    else
        if [[ "$KCP" = "true" ]]; then
            vlessKCPConfig
            return 0
        be
        # VLESS+TCP
        if [[ "$WS" = "false" ]]; then
            # VLESS+TCP+TLS
            if [[ "$XTLS" = "false" ]]; then
                vlessTLSConfig
            # VLESS+TCP+XTLS
            else
                vlessXTLSConfig
            be
        # VLESS+WS+TLS
        else
            vlessWSConfig
        be
    be
}

install() {
    getData

    $PMT clean all
    [[ "$PMT" = "apt" ]] && $PMT update
    #echo $CMD_UPGRADE | bash
    $CMD_INSTALL wget vim unzip tar gcc openssl
    $CMD_INSTALL net-tools
    if [[ "$PMT" = "apt" ]]; then
        $CMD_INSTALL libssl-dev g++
    be
    res=`which unzip 2>/dev/null`
    if [[ $? -ne 0 ]]; then
        colorEcho $RED "unzip installation failed, please check network"
        exit 1
    be

    installNginx
    setFirewall
    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        getCert
    be
    configNginx

    colorEcho $BLUE "Install V2ray..."
    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]]; then
        colorEcho $BLUE "The latest version of V2ray ${CUR_VER} has been installed"
    elif [[ $RETVAL == 3 ]]; then
        exit 1
    else
        colorEcho $BLUE "install V2Ray ${NEW_VER},architecture $(archAffix)"
        installV2ray
    be

    configV2ray

    setSelinux
    installBBR

    start
    showInfo

    bbrReboot
}

bbrReboot() {
    if [[ "${INSTALL_BBR}" == "true" ]]; then
        echo  
        echo "In order for the BBR module to take effect, the system will restart after 30 seconds"
        echo  
        echo -e "You can press ctrl + c to cancel the reboot, enter ${RED}reboot${PLAIN} to reboot the system later"
        sleep 30
        reboot
    be
}

update() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be

    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]]; then
        colorEcho $BLUE "The latest version of V2ray ${CUR_VER} has been installed"
    elif [[ $RETVAL == 3 ]]; then
        exit 1
    else
        colorEcho $BLUE "install V2Ray ${NEW_VER},architecture $(archAffix)"
        installV2ray
        stop
        start

        colorEcho $GREEN "The latest version of V2ray is installed successfully!"
    be
}

uninstall() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be

    echo ""
    read -p "Are you sure you want to uninstall V2ray? [y/n]:" answer
    if [[ "${answer,,}" = "y" ]]; then
        domain=`grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        if [[ "$domain" = "" ]]; then
            domain=`grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        be
        
        stop
        systemctl disable v2ray
        rm -rf $SERVICE_FILE
        rm -rf /etc/v2ray
        rm -rf /usr/bin/v2ray

        if [[ "$BT" = "false" ]]; then
            systemctl disable nginx
            $CMD_REMOVE nginx
            if [[ "$PMT" = "apt" ]]; then
                $CMD_REMOVE nginx-common
            be
            rm -rf /etc/nginx/nginx.conf
            if [[ -f /etc/nginx/nginx.conf.bak ]]; then
                mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
            be
        be
        if [[ "$domain" != "" ]]; then
            rm -rf $NGINX_CONF_PATH${domain}.conf
        be
        [[ -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --uninstall
        colorEcho $GREEN "V2ray uninstalled successfully"
    be
}

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be
    stopNginx
    startNginx
    systemctl restart v2ray
    sleep 2
    port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`
    res=`ss -nutlp| grep ${port} | grep -i v2ray`
    if [[ "$res" = "" ]]; then
        colorEcho $RED "v2ray failed to start, please check the log or see if the port is occupied!"
    else
        colorEcho $BLUE "v2ray started successfully"
    be
}

stop() {
    stopNginx
    systemctl stop v2ray
    colorEcho $BLUE "V2ray stopped successfully"
}


restart() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be

    stop
    start
}

getConfigFileInfo() {
    vless="false"
    tls="false"
    ws="false"
    xtls="false"
    trojan="false"
    protocol="VMess"
    kcp="false"

    uid=`grep id $CONFIG_FILE | head -n1| cut -d: -f2 | tr -d \",' '`
    alterid=`grep alterId $CONFIG_FILE  | cut -d: -f2 | tr -d \",' '`
    network=`grep network $CONFIG_FILE  | tail -n1| cut -d: -f2 | tr -d \",' '`
    [[ -z "$network" ]] && network="tcp"
    domain=`grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    if [[ "$domain" = "" ]]; then
        domain=`grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        if [[ "$domain" != "" ]]; then
            ws="true"
            tls="true"
            wspath=`grep path $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        be
    else
        tls="true"
    be
    if [[ "$ws" = "true" ]]; then
        port=`grep -i ssl $NGINX_CONF_PATH${domain}.conf| head -n1 | awk '{print $2}'`
    else
        port=`grep port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    be
    res=`grep -i kcp $CONFIG_FILE`
    if [[ "$res" != "" ]]; then
        kcp="true"
        type=`grep header -A 3 $CONFIG_FILE | grep 'type' | cut -d: -f2 | tr -d \",' '`
        seed=`grep seed $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
    be

    vmess=`grep vmess $CONFIG_FILE`
    if [[ "$vmess" = "" ]]; then
        trojan=`grep trojan $CONFIG_FILE`
        if [[ "$trojan" = "" ]]; then
            vless="true"
            protocol="VLESS"
        else
            trojan="true"
            password=`grep password $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
            protocol="trojan"
        be
        tls="true"
        encryption="none"
        xtls=`grep xtlsSettings $CONFIG_FILE`
        if [[ "$xtls" != "" ]]; then
            xtls="true"
            flow=`grep flow $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        else
            flow="无"
        be
    be
}

outputVmess() {
    raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"$IP\",
  \"port\":\"${port}\",
  \"id\":\"${uid}\",
  \"aid\":\"$alterid\",
  \"net\":\"tcp\",
  \"type\":\"none\",
  \"host\":\"\",
  \"path\":\"\",
  \"tls\":\"\"
}"
    link=`echo -n ${raw} | base64 -w 0`
    link="vmess://${link}"

    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}额外id(alterid)：${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "${BLUE} encryption method (security): ${PLAIN} ${RED}auto${PLAIN}"
    echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
    echo  
    echo -e "   ${BLUE}vmess链接:${PLAIN} $RED$link$PLAIN"
}

outputVmessKCP() {
    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}额外id(alterid)：${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "${BLUE} encryption method (security): ${PLAIN} ${RED}auto${PLAIN}"
    echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "${BLUE} masquerading type (type): ${PLAIN} ${RED}${type}${PLAIN}"
    echo -e "   ${BLUE}mkcp seed：${PLAIN} ${RED}${seed}${PLAIN}"
}

outputTrojan() {
    if [[ "$xtls" = "true" ]]; then
        echo -e "   ${BLUE}IP/域名(address): ${PLAIN} ${RED}${domain}${PLAIN}"
        echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
        echo -e "   ${BLUE}密码(password)：${PLAIN}${RED}${password}${PLAIN}"
        echo -e "   ${BLUE}流控(flow)：${PLAIN}$RED$flow${PLAIN}"
        echo -e "   ${BLUE}加密(encryption)：${PLAIN} ${RED}none${PLAIN}"
        echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
        echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}XTLS${PLAIN}"
    else
        echo -e "   ${BLUE}IP/域名(address): ${PLAIN} ${RED}${domain}${PLAIN}"
        echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
        echo -e "   ${BLUE}密码(password)：${PLAIN}${RED}${password}${PLAIN}"
        echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
        echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}TLS${PLAIN}"
    be
}

outputVmessTLS() {
    raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"$IP\",
  \"port\":\"${port}\",
  \"id\":\"${uid}\",
  \"aid\":\"$alterid\",
  \"net\":\"${network}\",
  \"type\":\"none\",
  \"host\":\"${domain}\",
  \"path\":\"\",
  \"tls\":\"tls\"
}"
    link=`echo -n ${raw} | base64 -w 0`
    link="vmess://${link}"
    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}额外id(alterid)：${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "${BLUE} encryption method (security): ${PLAIN} ${RED}none${PLAIN}"
    echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "${BLUE} disguised domain name/hostname (host)/SNI/peer name: ${PLAIN}${RED}${domain}${PLAIN}"
    echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}TLS${PLAIN}"
    echo  
    echo -e "   ${BLUE}vmess链接: ${PLAIN}$RED$link$PLAIN"
}

outputVmessWS() {
    raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"$IP\",
  \"port\":\"${port}\",
  \"id\":\"${uid}\",
  \"aid\":\"$alterid\",
  \"net\":\"${network}\",
  \"type\":\"none\",
  \"host\":\"${domain}\",
  \"path\":\"${wspath}\",
  \"tls\":\"tls\"
}"
    link=`echo -n ${raw} | base64 -w 0`
    link="vmess://${link}"

    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}额外id(alterid)：${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "${BLUE} encryption method (security): ${PLAIN} ${RED}none${PLAIN}"
    echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "${BLUE} masquerading type (type): ${PLAIN}${RED}none$PLAIN"
    echo -e "${BLUE} disguised domain name/hostname (host)/SNI/peer name: ${PLAIN}${RED}${domain}${PLAIN}"
    echo -e "   ${BLUE}路径(path)：${PLAIN}${RED}${wspath}${PLAIN}"
    echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}TLS${PLAIN}"
    echo  
    echo -e "   ${BLUE}vmess链接:${PLAIN} $RED$link$PLAIN"
}

showInfo() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be

    echo ""
    echo -n -e "${BLUE}V2ray running status: ${PLAIN}"
    statusText
    echo -e " ${BLUE}V2ray configuration file: ${PLAIN} ${RED}${CONFIG_FILE}${PLAIN}"
    colorEcho $BLUE "V2ray configuration information:"

    getConfigFileInfo

    echo -e "   ${BLUE}协议: ${PLAIN} ${RED}${protocol}${PLAIN}"
    if [[ "$trojan" = "true" ]]; then
        outputTrojan
        return 0
    be
    if [[ "$vless" = "false" ]]; then
        if [[ "$kcp" = "true" ]]; then
            outputVmessKCP
            return 0
        be
        if [[ "$tls" = "false" ]]; then
            outputVmess
        elif [[ "$ws" = "false" ]]; then
            outputVmessTLS
        else
            outputVmessWS
        be
    else
        if [[ "$kcp" = "true" ]]; then
            echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
            echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
            echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
            echo -e "   ${BLUE}加密(encryption)：${PLAIN} ${RED}none${PLAIN}"
            echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
            echo -e "${BLUE} masquerading type (type): ${PLAIN} ${RED}${type}${PLAIN}"
            echo -e "   ${BLUE}mkcp seed：${PLAIN} ${RED}${seed}${PLAIN}"
            return 0
        be
        if [[ "$xtls" = "true" ]]; then
            echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
            echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
            echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
            echo -e "   ${BLUE}流控(flow)：${PLAIN}$RED$flow${PLAIN}"
            echo -e "   ${BLUE}加密(encryption)：${PLAIN} ${RED}none${PLAIN}"
            echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
            echo -e "${BLUE} masquerading type (type): ${PLAIN}${RED}none$PLAIN"
            echo -e "${BLUE} disguised domain name/hostname (host)/SNI/peer name: ${PLAIN}${RED}${domain}${PLAIN}"
            echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}XTLS${PLAIN}"
        elif [[ "$ws" = "false" ]]; then
            echo -e "   ${BLUE}IP(address):  ${PLAIN}${RED}${IP}${PLAIN}"
            echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
            echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
            echo -e "   ${BLUE}流控(flow)：${PLAIN}$RED$flow${PLAIN}"
            echo -e "   ${BLUE}加密(encryption)：${PLAIN} ${RED}none${PLAIN}"
            echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
            echo -e "${BLUE} masquerading type (type): ${PLAIN}${RED}none$PLAIN"
            echo -e "${BLUE} disguised domain name/hostname (host)/SNI/peer name: ${PLAIN}${RED}${domain}${PLAIN}"
            echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}TLS${PLAIN}"
        else
            echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
            echo -e "   ${BLUE}端口(port)：${PLAIN}${RED}${port}${PLAIN}"
            echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"
            echo -e "   ${BLUE}流控(flow)：${PLAIN}$RED$flow${PLAIN}"
            echo -e "   ${BLUE}加密(encryption)：${PLAIN} ${RED}none${PLAIN}"
            echo -e "${BLUE} transport protocol (network): ${PLAIN} ${RED}${network}${PLAIN}"
            echo -e "${BLUE} masquerading type (type): ${PLAIN}${RED}none$PLAIN"
            echo -e "${BLUE} disguised domain name/hostname (host)/SNI/peer name: ${PLAIN}${RED}${domain}${PLAIN}"
            echo -e "   ${BLUE}路径(path)：${PLAIN}${RED}${wspath}${PLAIN}"
            echo -e "${BLUE} underlying security transport (tls): ${PLAIN}${RED}TLS${PLAIN}"
        be
    be
}

showLog() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorEcho $RED "V2ray is not installed, please install it first!"
        return
    be

    journalctl -xen -u v2ray --no-pager
}

menu() {
    clear
    echo "#############################################################"
    echo -e "# ${RED}v2ray one-click installation script ${PLAIN} #"
    echo -e "# ${GREEN}author${PLAIN}: network jump (hijk) #"
    echo -e "# ${GREEN}URL${PLAIN}: https://hijk.art #"
    echo -e "# ${GREEN}forum${PLAIN}: https://hijk.club #"
    echo -e "# ${GREEN}TG群${PLAIN}: https://t.me/hijkclub                               #"
    echo -e "# ${GREEN}Youtube Channel${PLAIN}: https://youtube.com/channel/UCYTB--VsObzepVJtc9yvUxQ #"
    echo "#############################################################"

    echo -e " ${GREEN}1.${PLAIN} install V2ray-VMESS"
    echo -e "  ${GREEN}2.${PLAIN}   安装V2ray-${BLUE}VMESS+mKCP${PLAIN}"
    echo -e " ${GREEN}3.${PLAIN} install V2ray-VMESS+TCP+TLS"
    echo -e " ${GREEN}4.${PLAIN} install V2ray-${BLUE}VMESS+WS+TLS${PLAIN}${RED}(recommended)${PLAIN}"
    echo -e "  ${GREEN}5.${PLAIN}   安装V2ray-${BLUE}VLESS+mKCP${PLAIN}"
    echo -e " ${GREEN}6.${PLAIN} install V2ray-VLESS+TCP+TLS"
    echo -e "${GREEN}7.${PLAIN} install V2ray-${BLUE}VLESS+WS+TLS${PLAIN}${RED}(can pass cdn)${PLAIN}"
    echo -e "${GREEN}8.${PLAIN} install V2ray-${BLUE}VLESS+TCP+XTLS${PLAIN}${RED}(recommended)${PLAIN}"
    echo -e "${GREEN}9.${PLAIN} install ${BLUE}trojan${PLAIN}${RED}(recommended)${PLAIN}"
    echo -e "${GREEN}10.${PLAIN} install ${BLUE}trojan+XTLS${PLAIN}${RED}(recommended)${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}11.${PLAIN}  更新V2ray"
    echo -e "  ${GREEN}12.  ${RED}卸载V2ray${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}13.${PLAIN} start V2ray"
    echo -e " ${GREEN}14.${PLAIN} restart V2ray"
    echo -e "  ${GREEN}15.${PLAIN}  停止V2ray"
    echo " -------------"
    echo -e " ${GREEN}16.${PLAIN} View V2ray configuration"
    echo -e " ${GREEN}17.${PLAIN} View V2ray log"
    echo " -------------"
    echo -e "${GREEN}0.${PLAIN} exit"
    echo -n "Current status:"
    statusText
    echo 

    read -p "Please select operation [0-17]:" answer
    case $answer in
        0)
            exit 0
            ;;
        1)
            install
            ;;
        2)
            KCP="true"
            install
            ;;
        3)
            TLS="true"
            install
            ;;
        4)
            TLS="true"
            WS="true"
            install
            ;;
        5)
            VLESS="true"
            KCP="true"
            install
            ;;
        6)
            VLESS="true"
            TLS="true"
            install
            ;;
        7)
            VLESS="true"
            TLS="true"
            WS="true"
            install
            ;;
        8)
            VLESS="true"
            TLS="true"
            XTLS="true"
            install
            ;;
        9)
            TROJAN="true"
            TLS="true"
            install
            ;;
        10)
            TROJAN="true"
            TLS="true"
            XTLS="true"
            install
            ;;
        11)
            update
            ;;
        12)
            uninstall
            ;;
        13)
            start
            ;;
        14)
            restart
            ;;
        15)
            stop
            ;;
        16)
            showInfo
            ;;
        17)
            showLog
            ;;
        *)
            colorEcho $RED "Please select the correct action!"
            exit 1
            ;;
    esac
}

checkSystem

action=$1
[[ -z $1 ]] && action=menu
case "$action" in
    menu|update|uninstall|start|restart|stop|showInfo|showLog)
        ${action}
        ;;
    *)
        echo "parameter error"
        echo " 用法: `basename $0` [menu|update|uninstall|start|restart|stop|showInfo|showLog]"
        ;;
esac
