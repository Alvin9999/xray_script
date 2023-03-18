#!/bin/bash

# 打印彩色文字
red() {
	echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
	echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
	echo -e "\033[33m\033[01m$1\033[0m"
}

# 检测 root 权限
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 系统相关
CMD=(
	"$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)"
	"$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)"
	"$(lsb_release -sd 2>/dev/null)"
	"$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)"
	"$(grep . /etc/redhat-release 2>/dev/null)"
	"$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')"
)

# 偷来的遗留
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 系统包管理器相关
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

for i in "${CMD[@]}"; do
	SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
	[[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统，请使用主流的操作系统" && exit 1
[[ -z $(type -P curl) ]] && ${PACKAGE_UPDATE[int]} && ${PACKAGE_INSTALL[int]} curl

# 生成随机的超时秒数以对抗 GFW 的主动探测

handshake=$(((($RANDOM*6)/32768)+4)) #4-10
connIdle=$(((($RANDOM*201)/32768)+300)) # 300-500
uplinkOnly=$(((($RANDOM*9)/32768)+2)) # 2-10
downlinkOnly=$(((($RANDOM*11)/32768)+5)) # 5-15

set_VMess_withoutTLS() {
    echo ""
    read -p "请输入 VMess 监听端口(默认随机): " port
    [[ -z "${port}" ]] && port=$(shuf -i200-65000 -n1)
    if [[ "${port:0:1}" == "0" ]]; then
        red "端口不能以0开头"
        port=$(shuf -i200-65000 -n1) #随机生成端口
    fi
    yellow "当前端口: $port"
    echo ""
    uuid=$(xray uuid) # 直接调用 Xray 的 uuid 指令以检测 是否安装 Xray
    [[ -z "$uuid" ]] && red "请先安装 Xray !" && exit 1 # 其实是历史遗留，顺便做了个功能
    getUUID
    yellow "当前uuid: $uuid"
    echo ""
    yellow "底层传输协议: "
    yellow "1. TCP(默认)"
    yellow "2. websocket(ws) (推荐)"
    yellow "3. mKCP"
    yellow "4. HTTP/2"
    green "5. gRPC"
    echo ""
    read -p "请选择: " answer
    case $answer in
        1) transport="tcp" ;;
        2) transport="ws" ;;
        3) transport="mKCP" ;;
        4) transport="http" ;;
        5) transport="gRPC" ;;
        *) transport="tcp" ;;
    esac

    if [[ "$transport" == "tcp" ]]; then
        yellow "伪装方式: "
        yellow "1. none(默认，无伪装)"
        yellow "2. http(可免流)"
        read -p "请选择: " answer
        if [[ "$answer" == "2" ]]; then
            read -p "请输入伪装域名(不一定是自己的，默认: a.189.cn): " host
            [[ -z "$host" ]] && host="a.189.cn"
            read -p "请输入路径(以"/"开头，默认随机): " path
            while true; do
                if [[ -z "${path}" ]]; then
                    tmp=$(openssl rand -hex 6)
                    path="/$tmp"
                    break
                elif [[ "${path:0:1}" != "/" ]]; then
                    red "伪装路径必须以/开头！"
                    path=""
                else
                    break
                fi
            done
            cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
            "levels": {
                "1": {
                    "handshake": $handshake,
                    "connIdle": $connIdle,
                    "uplinkOnly": $uplinkOnly,
                    "downlinkOnly": $downlinkOnly
                }
            }
    },
  "inbounds": [
    {
      "port": $port,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 1,
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "tcpSettings": {
            "header": {
                "type": "http",
                "request": {
                    "path": ["$path"],
                    "headers": {
                        "Host": ["$host"]
                    }
                },
                "response": {
                    "version": "1.1",
                    "status": "200",
                    "reason": "OK"
                }
            }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        echo ""
        ip=$(curl ip.sb)
        yellow "协议: VMess"
        yellow "ip: $ip"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "传输模式: TCP"
        yellow "伪装类型: http"
        yellow "伪装域名: $host"
        yellow "路径: $path"
        echo ""
# 来自 网络跳跃
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"tcp\",
  \"type\":\"http\",
  \"host\":\"${host}\",
  \"path\":\"${path}\",
  \"tls\":\"\"
}"
        link=$(echo -n ${raw} | base64 -w 0)
        shareLink="vmess://${link}"
        yellow "分享链接: "
        green "$shareLink"

        else
            cat >/usr/local/etc/xray/config.json <<-EOF
{
  "inbounds": [
    {
      "port": $port,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
            echo ""
            ip=$(curl ip.sb)
            yellow "协议: VMess"
            yellow "ip: $ip"
            yellow "端口: $port"
            yellow "uuid: $uuid"
            yellow "传输模式: TCP"
            yellow "伪装类型: http"
            yellow "伪装域名: $host"
            yellow "路径: $path"
            echo ""
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"tcp\",
  \"type\":\"none\",
  \"host\":\"\",
  \"path\":\"\",
  \"tls\":\"\"
}"
            link=$(echo -n ${raw} | base64 -w 0)
            shareLink="vmess://${link}"
            yellow "分享链接(v2RayN): "
            green "$shareLink"
            echo ""
            newLink="${uuid}@${ip}:${port}"
            yellow "分享链接(Xray标准): "
            green "vmess://${newLink}"
        fi


    elif [[ "$transport" == "ws" ]]; then
        echo ""
        read -p "请输入路径(以"/"开头，默认随机): " path
        while true; do
            if [[ -z "${path}" ]]; then
                tmp=$(openssl rand -hex 6)
                path="/$tmp"
                break
            elif [[ "${path:0:1}" != "/" ]]; then
                red "伪装路径必须以/开头！"
                path=""
            else
                break
            fi
        done
        yellow "当前路径: $path"
        echo ""
        read -p "请输入ws域名: 可用于免流(默认 a.189.cn): " host
        [[ -z "$host" ]] && host="a.189.cn"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
            "levels": {
                "1": {
                    "handshake": $handshake,
                    "connIdle": $connIdle,
                    "uplinkOnly": $uplinkOnly,
                    "downlinkOnly": $downlinkOnly
                }
            }
    },
  "inbounds": [
    {
      "port": $port,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "level": 1,
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network":"ws",
        "wsSettings": {
            "path": "$path",
            "headers": {
                "Host": "$host"
            }
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        ip=$(curl ip.sb)
        echo ""
        yellow "协议: VMess"
        yellow "ip: $ip"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输方式: ws(websocket)"
        yellow "路径: $path 或 ${path}?ed=2048 (后面这个延迟更低，但可能增加特征)"
        yellow "ws host(伪装域名): $host"
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"ws\",
  \"host\":\"${host}\",
  \"path\":\"${path}\",
  \"tls\":\"\"
}"
        link=$(echo -n ${raw} | base64 -w 0)
        shareLink="vmess://${link}"
        echo ""
        yellow "分享链接: "
        green "$shareLink"
        newPath=$(echo -n $path | xxd -p | tr -d '\n' | sed 's/\(..\)/%\1/g')
        newLink="${uuid}@${ip}:${port}?type=ws&host=${host}&path=${newPath}"
        yellow "分享链接(Xray标准): "
        green "vmess://${newLink}"


    elif [[ "$transport" == "mKCP" ]]; then
        echo ""
        yellow "下行带宽:"
        yellow "单位: MB/s，注意是 Byte 而非 bit"
        yellow "默认: 100"
        yellow "建议设置为一个较大值"
        read -p "请设置: " uplinkCapacity
        [[ -z "$uplinkCapacity" ]] && uplinkCapacity=100
        yellow "当前上行带宽: $uplinkCapacity"
        echo ""
        yellow "上行带宽: "
        yellow "单位: MB/s，注意是 Byte 而非 bit"
        yellow "默认: 100"
        yellow "建议设为你的真实上行带宽到它的两倍"
        read -p "请设置: " downlinkCapacity
        [[ -z "$downlinkCapacity" ]] && downlinkCapacity=100
        yellow "当前下行带宽: $downlinkCapacity"
        echo ""
        yellow "伪装类型: "
        yellow "1. 不伪装:none(默认)"
        yellow "2. SRTP: 伪装成 SRTP 数据包，会被识别为视频通话数据（如 FaceTime）"
        yellow "3. uTP: 伪装成 uTP 数据包，会被识别为 BT 下载数据"
        yellow "4. wechat-video: 伪装成微信视频通话的数据包"
        yellow "5. DTLS: 伪装成 DTLS 1.2 数据包"
        yellow "6. wireguard: 伪装成 WireGuard 数据包。（并不是真正的 WireGuard 协议）"
        read -p "请选择: " answer
        case $answer in
            1) camouflageType="none" ;;
            2) camouflageType="srtp" ;;
            3) camouflageType="utp" ;;
            4) camouflageType="wechat-video" ;;
            5) camouflageType="dtls" ;;
            6) camouflageType="wireguard" ;;
            *) camouflageType="none" ;;
        esac
        yellow "当前伪装: $camouflageType"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "port": ${port},
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 1,
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "mkcp",
                "kcpSettings": {
                    "uplinkCapacity": ${uplinkCapacity},
                    "downlinkCapacity": ${downlinkCapacity},
                    "congestion": true,
                    "header": {
                        "type": "${camouflageType}"
                    }
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ]
}
EOF
        echo ""
        ip=$(curl ip.sb)
        yellow "协议: VMess"
        yellow "传输协议: mKCP"
        yellow "ip: $ip"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "伪装类型: $camouflageType"
        yellow "上行带宽: $uplinkCapacity"
        yellow "下行带宽: $downlinkCapacity"
        yellow "mKCP seed(混淆密码): 无"
        echo ""
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"kcp\",
  \"type\":\"$camouflageType\",
  \"tls\":\"\"
}"
        link=$(echo -n ${raw} | base64 -w 0)
        shareLink="vmess://${link}"
        yellow "分享链接: "
        green "$shareLink"
        newLink="${uuid}@${ip}:${port}?type=kcp&headerType=$camouflageType"
        yellow "分享链接(Xray标准): "
        green "vmess://${newLink}"


    elif [[ "$transport" == "http" ]]; then
        echo ""
        red "警告: 由于 HTTP/2 官方的建议， Xray 客户端的 HTTP/2 须强制开启TLS。故本功能仅作为后端使用，因此只监听本地地址(127.0.0.1)"
        red "不懂的可以不填域名以退出"
        read -p "请输入域名: " domain
        [[ -z "$domain" ]] && red "请输入域名！" && exit 1
        yellow "当前域名: $domain"
        echo ""
        read -p "请输入路径(以"/"开头，默认随机): " path
        while true; do
            if [[ -z "${path}" ]]; then
                tmp=$(openssl rand -hex 6)
                path="/$tmp"
                break
            elif [[ "${path:0:1}" != "/" ]]; then
                red "伪装路径必须以/开头！"
                path=""
            else
                break
            fi
        done
        yellow "当前路径: $path"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
  "inbounds": [
    {
      "listen": "127.0.0.1"
      "port": $port,
      "protocol": "vmess",
      "streamSettings": {
        "network": "http",
        "httpSettings": {
            "host": [
                "$domain"
            ],
            "path": "$path"
        }
      },
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "alterId": 0
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        echo ""
        yellow "协议: VMess"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输协议: HTTP/2(http)"
        yellow "域名: $domain"
        yellow "路径: $path"
        echo ""
        yellow "提示: 客户端不能直接连接！服务端只监听 127.0.0.1 "


    elif [[ "$transport" == "gRPC" ]]; then
        echo ""
        red "警告: 客户端仅开启TLS才能连接，所以这里只监听 127.0.0.1"
        red "不懂的请退出"
        yellow "server name: "
        yellow "作用类似于ws中的"path""
        read -p "请输入: " serverName
        while true; do
            if [[ -z "${serverName}" ]]; then
                serverName=$(openssl rand -hex 6)
                break
            else
                break
            fi
        done
        yellow "当前server name: $serverName"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": $port,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "$serviceName"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
        echo ""
        yellow "协议: VMess"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输方式: gRPC"
        yellow "server name: $serverName"

        
    fi 
    systemctl stop xray
    systemctl start xray
    ufw allow $port
    ufw reload
}

set_VLESS_withoutTLS() {
    echo ""
    red "警告: 会覆盖原有配置!"
    echo ""
    read -p "请输入 VLESS 监听端口: " port
    [[ -z "${port}" ]] && port=$(shuf -i200-65000 -n1)
    if [[ "${port:0:1}" == "0" ]]; then
        red "端口不能以0开头"
        port=$(shuf -i200-65000 -n1)
    fi
    yellow "当前端口: $port"
    echo ""
    uuid=$(xray uuid)
    [[ -z "$uuid" ]] && red "请先安装 Xray !" && exit 1
    getUUID
    yellow "当前uuid: $uuid"
    echo ""
    yellow "底层传输协议: "
    yellow "注: 由于 VLESS 是明文传输，所以砍掉了tcp;除 mKCP 外，其他选项都监听 127.0.0.1!"
    yellow "1. websocket(ws) (推荐)"
    yellow "2. mKCP (默认)"
    yellow "3. HTTP/2"
    green "4. gRPC"
    echo ""
    read -p "请选择: " answer
    case $answer in
        1) transport="ws" ;;
        2) transport="mKCP" ;;
        3) transport="http" ;;
        4) transport="gRPC" ;;
        *) transport="mKCP" ;;
    esac
    yellow "当前底层传输协议: $transport"
    echo ""

    if [[ "$transport" == "ws" ]] ;then
        read -p "请输入路径(以"/"开头，默认随机): " path
        while true; do
            if [[ -z "${path}" ]]; then
                tmp=$(openssl rand -hex 6)
                path="/$tmp"
                break
            elif [[ "${path:0:1}" != "/" ]]; then
                red "伪装路径必须以/开头！"
                path=""
            else
                break
            fi
        done
        yellow "当前路径: $path"
        echo ""
        read -p "请输入ws域名: (默认 a.189.cn): " host
        [[ -z "$host" ]] && host="a.189.cn"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": $port,
            "protocol": "VLESS",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "$path",
                    "headers": {
                        "Host": "$host"
                    }
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
        echo ""
        yellow "协议: VLESS"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输方式: ws(websocket)"
        yellow "路径: $path 或 ${path}?ed=2048 (后面这个延迟更低，但可能增加特征)"
        yellow "ws host(伪装域名): $host"
    

    elif [[ "$transport" == "mKCP" ]] ;then
        echo ""
        yellow "下行带宽:"
        yellow "单位: MB/s，注意是 Byte 而非 bit"
        yellow "默认: 100"
        yellow "建议设置为一个较大值"
        read -p "请设置: " uplinkCapacity
        [[ -z "$uplinkCapacity" ]] && uplinkCapacity=100
        yellow "当前上行带宽: $uplinkCapacity"
        echo ""
        yellow "上行带宽: "
        yellow "单位: MB/s，注意是 Byte 而非 bit"
        yellow "默认: 100"
        yellow "建议设为你的真实上行带宽到它的两倍"
        read -p "请设置: " downlinkCapacity
        [[ -z "$downlinkCapacity" ]] && downlinkCapacity=100
        yellow "当前下行带宽: $downlinkCapacity"
        echo ""
        read -p "混淆密码(默认随机): " seed
        [[ -z "$seed" ]] && seed=$(openssl rand -base64 16)
        yellow "当前混淆密码: $seed"
        echo ""
        yellow "伪装类型: "
        yellow "1. 不伪装:none(默认)"
        yellow "2. SRTP: 伪装成 SRTP 数据包，会被识别为视频通话数据（如 FaceTime）"
        yellow "3. uTP: 伪装成 uTP 数据包，会被识别为 BT 下载数据"
        yellow "4. wechat-video: 伪装成微信视频通话的数据包"
        yellow "5. DTLS: 伪装成 DTLS 1.2 数据包"
        yellow "6. wireguard: 伪装成 WireGuard 数据包。（并不是真正的 WireGuard 协议）"
        read -p "请选择: " answer
        case $answer in
            1) camouflageType="none" ;;
            2) camouflageType="srtp" ;;
            3) camouflageType="utp" ;;
            4) camouflageType="wechat-video" ;;
            5) camouflageType="dtls" ;;
            6) camouflageType="wireguard" ;;
            *) camouflageType="none" ;;
        esac
        yellow "当前伪装: $camouflageType"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "port": ${port},
            "protocol": "VLESS",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "mkcp",
                "kcpSettings": {
                    "uplinkCapacity": ${uplinkCapacity},
                    "downlinkCapacity": ${downlinkCapacity},
                    "congestion": true,
                    "header": {
                        "type": "${camouflageType}"
                    },
                    "seed": "$seed"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ]
}
EOF
        echo ""
        ip=$(curl ip.sb)
        yellow "协议: VLESS"
        yellow "传输协议: mKCP"
        yellow "ip :$ip"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "伪装类型: $camouflageType"
        yellow "上行带宽: $uplinkCapacity"
        yellow "下行带宽: $downlinkCapacity"
        yellow "mKCP seed(混淆密码): $seed"
        echo ""
        newSeed=$(echo -n $seed | xxd -p | tr -d '\n' | sed 's/\(..\)/%\1/g')
        newLink="${uuid}@${ip}:${port}?type=kcp&headerType=${camouflageType}&seed=${newSeed}"
        yellow "分享链接(Xray标准): "
        green "vless://${newLink}"


    elif [[ "$transport" == "http" ]] ;then
        read -p "请输入域名: " domain
        [[ -z "$domain" ]] && red "请输入域名！" && exit 1
        yellow "当前域名: $domain"
        echo ""
        read -p "请输入路径(以"/"开头，默认随机): " path
        while true; do
            if [[ -z "${path}" ]]; then
                tmp=$(openssl rand -hex 6)
                path="/$tmp"
                break
            elif [[ "${path:0:1}" != "/" ]]; then
                red "路径必须以/开头！"
                path=""
            else
                break
            fi
        done
        yellow "当前路径: $path"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": "$port",
            "protocol": "VLESS",
            "streamSettings": {
                "network": "http",
                "httpSettings": {
                    "host": [
                        "$domain"
                    ],
                    "path": "$path"
                }
            },
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
        echo ""
        yellow "协议: VLESS"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输协议: HTTP/2(http)"
        yellow "域名: $domain"
        yellow "路径: $path"


    elif [[ "$transport" == "gRPC" ]] ;then
        echo ""
        red "警告: 客户端仅开启TLS才能连接，所以这里只监听 127.0.0.1"
        red "不懂的请退出"
        yellow "server name: "
        yellow "作用类似于ws中的"path""
        read -p "请输入: " serverName
        while true; do
            if [[ -z "${serverName}" ]]; then
                serverName=$(openssl rand -hex 6)
                break
            else
                break
            fi
        done
        yellow "当前server name: $serverName"
        cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": $port,
            "protocol": "VLESS",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 0,
                        "email": "love@xray.com"
                    }
                ],
                "decryption": "none"
            }
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "$serviceName"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
        echo ""
        yellow "协议: VMess"
        yellow "端口: $port"
        yellow "uuid: $uuid"
        yellow "额外ID: 0"
        yellow "传输方式: gRPC"
        yellow "server name: $serverName"
    fi

    systemctl stop xray
    systemctl start xray
    ufw allow $port
    ufw reload
}

# 偷懒了，毕竟 shadowsocks 原版没有 udp over tcp
set_shadowsocks_withoutTLS() {
    echo ""
    read -p "请输入 shadowsocks 监听端口(默认随机): " port
    [[ -z "${port}" ]] && port=$(shuf -i200-65000 -n1)
    if [[ "${port:0:1}" == "0" ]]; then
        red "端口不能以0开头"
        port=$(shuf -i200-65000 -n1)
    fi
    yellow "当前 shadowsocks 监听端口: $port"
    echo ""
    echo ""
    yellow "加密方式: "
    red "注: 带"2022"的为 shadowsocks-2022 加密方式，目前支持的客户端较少，但抗封锁性更强，且能开启 UDP over TCP"
    yellow "按推荐程度排序"
    echo ""
    green "1. 2022-blake3-aes-128-gcm"
    green "2. 2022-blake3-aes-256-gcm"
    green "3. 2022-blake3-chacha20-poly1305"
    yellow "4. aes-128-gcm(推荐)"
    yellow "5. aes-256-gcm"
    green "6. chacha20-ietf-poly1305(默认)"
    yellow "7. xchacha20-ietf-poly1305"
    red "8 none(不加密，选择后会自动只监听 127.0.0.1 )"
    echo ""
    read -p "请选择: " answer
    case $answer in
        1) method="2022-blake3-aes-128-gcm" && ss2022="true" ;;
        2) method="2022-blake3-aes-256-gcm" && ss2022="true" ;;
        3) method="2022-blake3-chacha20-poly1305" && ss2022="true" ;;
        4) method="aes-128-gcm" ;;
        5) method="aes-256-gcm" ;;
        6) method="chacha20-ietf-poly1305" ;;
        7) method="xchacha20-ietf-poly1305" ;;
        8) method="none" ;;
        *) method="chacha20-ietf-poly1305" ;;
    esac
    yellow "当前加密方式: $method"
    echo ""
    yellow "注意: 在 Xray 中，shadowsocks-2022都可以使用32位密码，但标准实现中，2022-blake3-aes-128-gcm使用16位密码，其他 Xray 支持的2022系加密使用32位密码。"
    yellow "不懂直接回车"
    yellow "16位密码: "
    openssl rand -base64 16
    read -p "请输入 shadowsocks 密码(默认32位): " password
    [[ -z "$password" ]] && password=$(openssl rand -base64 32)
    yellow "当前密码: $password"
    if [[ "$method" == "none" ]]; then
        listen="127.0.0.1"
    else
        listen="0.0.0.0"
    fi
    cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
            "levels": {
                "1": {
                    "handshake": $handshake,
                    "connIdle": $connIdle,
                    "uplinkOnly": $uplinkOnly,
                    "downlinkOnly": $downlinkOnly
                }
            }
    },
    "inbounds": [
        {
            "listen": "$listen",
            "port": $port,
            "protocol": "shadowsocks",
            "settings": {
                "password": "$password",
                "method": "$method",
                "level": 1,
                "email": "love@xray.com",
                "network": "tcp,udp"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
    echo ""
    ip=$(curl ip.sb)
    yellow "协议: shadowsocks"
    yellow "ip: $ip"
    yellow "端口: $port"
    yellow "加密方式: $method"
    yellow "密码: $password"
    echo ""
    raw="${method}:${password}@${ip}:${port}"
    if [[ "$ss2022" != "true" ]]; then
        link=$(echo -n ${raw} | base64 -w 0)
    else
        link="$raw"
    fi
    green "分享链接: "
    green "ss://$link"

    systemctl stop xray
    systemctl start xray
    ufw allow $port
    ufw reload
}

set_withoutTLS() {
    echo ""
    red "警告: 可能会删除原有配置!"
    yellow "请选择协议: "
    yellow "1. VMess"
    yellow "2. shadowsocks"
    yellow "3. VLESS(由于VLESS没有加密，请勿使用VLESS直接过墙!)"
    echo ""
    read -p "请选择: " protocol
    case $protocol in
        1) set_VMess_withoutTLS ;;
        2) set_shadowsocks_withoutTLS ;;
        3) set_VLESS_withoutTLS ;;
        *) red "请输入正确的选项！" ;;
    esac
}

set_withXTLS() {
    echo ""
    yellow "请确保: "
    yellow "1. 已安装 Xray"
    yellow "2. 申请了自己的 TLS 证书"
    yellow "3. 将使用系统的包管理器(重新)安装 nginx"
    red "4. 原 nginx 和 Xray 配置将被删除！！！"
    echo ""
    read -p "输入任意内容继续，按 ctrl + c 退出" rubbish
    echo ""
    echo ""
    echo ""
    
    read -p "请输入 VLESS 监听端口(默认443): " port
    [[ -z "${port}" ]] && port=443
    if [[ "${port:0:1}" == "0" ]]; then
        red "端口不能以0开头"
        port=443
    fi
    yellow "当前端口: $port"
    echo ""

    read -p "请输入回落网站端口(默认 80): " fallbackPort
    [[ -z "${fallbackPort}" ]] && fallbackPort=80
    if [[ "${fallbackPort:0:1}" == "0" ]]; then
        red "端口不能以0开头"
        fallbackPort=80
    fi
    yellow "当前端口: $fallbackPort"

    echo ""
    wsPort=$(shuf -i10000-65000 -n1)
    wsPath=$(openssl rand -hex 6)
    fallbackPort2=$(shuf -i10000-65000 -n1)

    portUsed=$(lsof -i :$port)
    fallbackPortUsed=$(lsof -i :$fallbackPort)
    wsPortUsed=$(lsof -i :$fallbackPort)
    fallbackPort2Used=$(lsof -i :$fallbackPort2)
    yellow "当前需要用到的端口占用: "
    yellow "$portUsed"
    echo ""
    yellow "$fallbackPortUsed"
    echo ""
    yellow "$wsPortUsed"
    echo ""
    yellow "$fallbackPort2Used"
    echo ""
    read -p "有占用请 ctrl + c 推出，无占用或强制执行请回车: " rubbish
    echo ""

    uuid=$(xray uuid)
    [[ -z "$uuid" ]] && red "请先安装 Xray !" && exit 1
    getUUID
    yellow "当前uuid: $uuid"

    yellow "流控: "
    green "1. xtls-rprx-vision,none(Xray v1.7.5 后被移除)"
    yellow "2. xtls-rprx-vision(默认)"
    yellow "3. xtls-rprx-direct (Xray v1.7.5 后被移除)"
    red "4 xtls-rprx-origin(不推荐)  (Xray v1.7.5 后被移除)"
    yellow "5. (不使用流控)"
    echo ""
    green "一些提示: "
    green "虽然旧的流控已被弃用，但考虑到新流控未经时间检验，使用旧流控有出其不意的效果"
    echo ""
    read -p "请选择: " answer
    case $answer in
        1) flow="xtls-rprx-vision,none" && flow2="xtls-rprx-vision" && TLS="tls" ;;
        2) flow="xtls-rprx-vision" && flow2="xtls-rprx-vision" && TLS="tls" ;;
        3) flow="xtls-rprx-direct" && flow2="xtls-rprx-direct" && TLS="xtls" ;;
        4) flow="xtls-rprx-origin" && flow2="xtls-rprx-origin" && TLS="xtls" ;;
        5) flow="" && flow2="" && TLS="tls" ;;
        *) red "已自动选择 xtls-rprx-vision!" && flow="xtls-rprx-vision" && flow2="xtls-rprx-vision" && TLS="tls" ;;
    esac
    yellow "当前流控: $flow"

    echo ""
    read -p "请输入你的域名: " domain
    yellow "当前域名: $domain"
    echo ""
    read -p "请输入证书路径(不要以'~'开头！): " cert
    if [[ ${cert:0:1} == "~" ]] || [ -z "$cert" ]; then
        red "请输入证书路径 或 证书路径不能以 ~ 开头！" && exit 1
    fi
    yellow "当前证书路径: $cert"
    echo ""
    read -p "请输入密钥路径(不要以'~'开头！): " key
    if [[ ${key:0:1} == "~" ]] || [ -z "$key" ]; then
        red "请输入密钥路径 或 密钥路径不能以 ~ 开头！" && exit 1
    fi
    yellow "当前密钥路径: $key"

    echo ""
    read -p "请输入反代网站网址(必须为 https 网站，默认: www.bing.com): " forwardWeb
    [ -z "$forwardWeb" ] && forwardWeb="www.bing.com"
    yellow "当前反代网站: $forwardWeb"
    echo ""

# 配置详解
# http/1.1 就回落到 80 端口，h2 回落到高位端口。毕竟浏览器不会使用 h2c。
# 反代网站对新手友好。

    green "正在安装 nginx ......"
    ${PACKAGE_UPDATE[int]}
    ${PACKAGE_INSTALL[int]} nginx
    echo ""
    green "正在生成 nginx 配置"
    cat >/etc/nginx/nginx.conf <<-EOF
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    gzip on;

    server {
        listen 0.0.0.0:$fallbackPort;
        listen [::]:$fallbackPort;
        listen 0.0.0.0:$fallbackPort2 http2;
        listen [::]:$fallbackPort2 http2;
        server_name $domain;

        location / {
            proxy_pass https://${forwardWeb};
            proxy_redirect off;
            proxy_ssl_server_name on;
            sub_filter_once off;
            sub_filter "${forwardWeb}" \$server_name;
            proxy_set_header Host "${forwardWeb}";
            proxy_set_header Referer \$http_referer;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header User-Agent \$http_user_agent;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "zh-CN";
        }

        location /${wsPath} {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:${wsPort};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }

    }
}
EOF

    systemctl enable nginx
    systemctl stop nginx
    systemctl start nginx

# 默认用户等级似乎是 0,但我整篇都搞成了 1。
# 将错就错吧，希望用户在浏览配置时能知道。

    echo ""
    green "正在配置 Xray"
    cp $cert /usr/local/etc/xray/cert.crt
    cp $key /usr/local/etc/xray/key.key
    cat >/usr/local/etc/xray/config.json <<-EOF
{
    "policy": {
        "levels": {
            "1": {
                "handshake": $handshake,
                "connIdle": $connIdle,
                "uplinkOnly": $uplinkOnly,
                "downlinkOnly": $downlinkOnly
            }
        }
    },
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 1,
                        "flow": "$flow"
                    }
                ],
                "fallbacks": [
                    {
                        "alpn": "h2",
                        "dest": $fallbackPort2
                    },
                    {
                        "alpn": "http/1.1",
                        "dest": $fallbackPort
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "${TLS}Settings": {
                    "certificates": [
                        {
                            "certificateFile": "/usr/local/etc/xray/cert.crt",
                            "keyFile": "/usr/local/etc/xray/key.key"
                        }
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": $wsPort,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "level": 1,
                        "alterId": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/${wsPath}"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF

    systemctl enable xray
    systemctl stop xray
    systemctl start xray
    ufw allow $port
    ufw reload

    ip=$(curl ip.sb)
    ipv6=$(curl ip.sb -6)
    if [ "$ip" == "$ipv6" ]; then
        linkIP="[$ip]"
    else
        linkIP="$ip"
    fi

    xtlsLink="vless://${uuid}@${linkIP}:${port}?sni=${domain}&security=${TLS}&type=tcp&flow=${flow2}"
    wsLink1="vmess://${uuid}@${linkIP}:${port}?sni=${domain}&security=${TLS}&type=ws&host=${domain}&path=${wsPath}"
raw="{
  \"v\":\"2\",
  \"ps\":\"\",
  \"add\":\"${ip}\",
  \"port\":\"${port}\",
  \"id\":\"${uuid}\",
  \"aid\":\"0\",
  \"net\":\"ws\",
  \"path\":\"${wsPath}\",
  \"host\":\"${domain}\",
  \"tls\":\"${TLS}\",
  \"sni\":\"${domain}\"
}"
    tmpLink=$(echo -n ${raw} | base64 -w 0)
    wsLink2="vmess://$tmpLink"
    tlsLink="vless://${uuid}@${linkIP}:${port}?sni=${domain}&security=tls&type=tcp"

    yellow "节点一:"
    yellow "协议: VLESS"
    yellow "地址: $ip 或 $domain"
    yellow "端口: $port"
    yellow "底层传输方式: TCP"
    yellow "传输层安全: $TLS"
    yellow "流控: $flow2"
    yellow "UUID: $uuid"
    yellow "服务名称指示(sni): $domain"
    echo ""
    green "分享链接: $xtlsLink"

    echo ""
    echo ""
    yellow "节点二:"
    yellow "协议: VMess"
    yellow "地址: $ip 或 $domain"
    yellow "端口: $port"
    yellow "底层传输方式: ws"
    yellow "ws 路径: $wsPath"
    yellow "ws host: $domain"
    yellow "传输层安全: TLS"
    yellow "UUID: $uuid"
    yellow "额外ID: 0"
    yellow "服务名称指示(sni): $domain"
    echo ""
    yellow "分享链接(DuckSoft): $wsLink1"
    echo ""
    green "分享链接(v2rayN): $wsLink2"

    if [ "$flow2" == "xtls-rprx-vision" ]; then
        yellow "节点三:"
        yellow "协议: VLESS"
        yellow "地址: $ip 或 $domain"
        yellow "端口: $port"
        yellow "传输层安全: TLS"
        yellow "UUID: $uuid"
        yellow "服务名称指示(sni): $domain"
        echo ""
        green "分享链接: $tlsLink"
    fi
}

set_REALITY_steal() {
    echo ""
    yellow " 请确保: "
    yellow " 1. 会使用 REALITY 客户端，不会用请离开"
    yellow " 2. 已用脚本的 1/2 选项 安装 Xray"
    echo ""
    read -p "输入任意内容继续，按 ctrl + c 退出" rubbish
    echo ""
    yellow " 请输入借用网站/ip，默认 dl.google.com: "
    read -p "" forwardSite
    [ -z "$forwardSite" ] && forwardSite="dl.google.com"
    yellow " 当前借用网站: $forwardSite"
    echo ""
    yellow " 请输入借用网站的 sni(默认与借用网站相同): "
    read -p "" forwardSiteSNI
    [ -z "$forwardSiteSNI" ] && forwardSiteSNI=$forwardSite
    yellow "当前借用网站的 sni: $forwardSiteSNI"
    echo ""
    yellow " 请输入目标网站端口(默认 443): "
    read -p "" forwardPort
    [ -z "$forwardPort" ] && forwardPort=443
    yellow " 当前目标端口: $port"
    echo ""
    red " 开始测试: "
# 目前没有找到能读取 curl 结果并判断是否成功的方法，只能由用户自行判断
    curl --http2 --tlsv1.3 https://${forwardSite}:${forwardPort}
    yellow " 请确保没有错误，然后按 y 继续"
    read -p " (Y/n) " rubbish
    if [ "$rubbish" != "Y" ] || [ "$rubbish" != "y" ]; then
        exit 0
    fi
    echo ""
    yellow " 请输入 Xray 监听端口(默认 443): "
    read -p "" port
    [ -z "$port" ] && port=443
    yellow " 当前 Xray 监听端口: $port"
    if [ "$port" == "443" ] && [ "$forwardPort" == "443" ]; then
        echo ""
        green " 当前 80 端口占用: "
        lsof -i:80
        echo ""
        yellow " 是否转发 80 端口?"
        read -p " (Y/n)" answer
        if [ "$answer" == "n" ] || [ "$answer" == "N" ]; then
            "DokodemoDoorPort"=$(shuf -i10000-65000 -n1)
        else
            "DokodemoDoorPort"=80
        fi
    fi
    echo ""
    h2Port=$(shuf -i10000-65000 -n1)
    red " 检测所需端口占用情况: "
    lsof -i:$port
    lsof -i:$DokodemoDoorPort
    lsof -i:$h2Port
    yellow " 如有占用，请使用 kill [pid] 来解除占用！"
    read -p "是否继续(Y/n)?" answer
    if [ "$answer" == "n" ];then
        exit 0
    fi
    echo ""
    getUUID
    echo ""
    yellow " 当前 uuid: $uuid"
    echo ""
    tmpKey=$(xray x25519)
    tmpPrivateKey=$(echo "$tmpKey" | grep Private | cut -d " " -f 3)
    tmpPublickKey=$(echo "$tmpKey" |  grep Public | cut -d " " -f 3)
    yellow " 请输入 REALITY 的公钥和私钥，不填将随机生成的！"
    read -p " 私钥(服务端): " answer
    if [ -z "$answer" ]; then
        red " 已随机生成密钥对！"
        PrivateKey="$tmpPrivateKey"
        PublicKey="$tmpPublickKey"
    else
        PrivateKey=$answer
        read -p " 公钥(客户端): " PublicKey
    fi
    echo ""
    yellow " 当前私钥: $PrivateKey"
    yellow " 当前公钥: $PubliccKey"
    echo ""
    yellow " 流控: "
    green " 1. xtls-rprx-vision (默认)"
    yellow "2.  (不使用流控)"
    echo ""
    read -p " 请选择: " answer
    case $answer in
        1) flow="xtls-rprx-vision" ;;
        2) flow="" ;;
        *) red "已自动选择 xtls-rprx-vision!" && flow="xtls-rprx-vision" ;;
    esac
    yellow " 当前流控: $flow"
    echo ""
    echo ""
    red " 开始配置 Xray!"
    cat >/usr/local/etc/xray/config.json <<-EOF
{
    "inbounds": [
        {
            "port": $port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid",
                        "flow": "$flow"
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": $h2Port
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "${forwardSite}:${forwardPort}",
                    "xver": 0,
                    "serverNames": [
                        "$forwardSiteSNI"
                    ],
                    "privateKey": "$PrivateKey",
                    "shortIds": [
                        ""
                    ]
                }
            }
        },
        {
            "listen": "127.0.0.1",
            "port": $h2Port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ],
                "decryption": "none",
            },
            "streamSettings": {
                "security": "none",
                "network": "h2",
                "httpSettings": {
                    "path": "/"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        },
        {
            "protocol": "Blackhole"
        }
    ]
}
EOF

    echo ""
    systemctl restart xray
    ufw allow $port
    if [ "$DokodemoDoorPort" == "80" ]; then
        ufw allow 80
    fi
    echo ""
    ip=$(curl ip.sb)
    ipv6=$(curl ip.sb -6)
    if [ "$ip" == "$ipv6" ]; then
        linkIP="[$ip]"
    else
        linkIP="$ip"
    fi
    yellow " 服务器信息: "
    echo ""
    red " 节点一: "
    green " 协议: VLESS"
    green " 服务器地址: $linkIP"
    green " 端口: $port"
    green " uuid: $uuid"
    green " 流控: $flow"
    green " 传输方式: tcp"
    green " 传输层安全: REALITY"
    green " 浏览器指纹: 任选，推荐 ios"
    green " serverName / 服务器名称指示 /sni: $forwardSiteSNI"
    green " publicKey / 公钥: $PublicKey"
    green " spiderX: 自行访问目标网站，找个靠谱的路径，不懂就填 \"/\" "
    green " shortId: 不懂不填"
    echo ""
    green " 分享链接： 暂无标准"
    echo ""
    echo ""
    red " 节点二:"
    green " 协议: VLESS"
    green " 服务器地址: $linkIP"
    green " 端口: $port"
    green " uuid: $uuid"
    green " 流控: none"
    green " 传输方式: HTTP/2"
    green " 路径: /"
    green " 传输层安全: REALITY"
    green " 浏览器指纹: 任选，推荐 ios"
    green " serverName / 服务器名称指示 /sni: $forwardSiteSNI"
    green " publicKey / 公钥: $PublicKey"
    green " spiderX: 自行访问目标网站，找个靠谱的路径，不懂就填 \"/\" "
    green " shortId: 不懂不填"
    echo ""
    green " 分享链接： 暂无标准"
}

install_build() {
    echo ""
    yellow "请确保: "
    yellow "1. 安装了最新版本的 golang(可使用本脚本102选项) 和 git"
    yellow "2. 自愿承担使用最新版本的风险(包括各种各样的bug、协议不适配等问题)"
    echo ""
    read -p "输入任意内容继续，按 ctrl + c 退出" rubbish
    echo ""
    red "3秒冷静期"
    sleep 3
    git clone https://github.com/XTLS/Xray-core.git
    yellow "即将开始编译，可能耗时较久，请耐心等待"
    cd Xray-core && go mod download
    CGO_ENABLED=0 go build -o xray -trimpath -ldflags "-s -w -buildid=" ./main
	chmod +x xray || {
		red "Xray安装失败"
        cd ..
        rm -rf Xray-core
        rm -rf /root/go
		exit 1
	}
    systemctl stop xray
    cp xray /usr/local/bin/
    cd ..
    rm -rf Xray-core/
    mkdir /usr/local/etc/xray 
    mkdir /usr/local/share/xray
    cd /usr/local/share/xray
    curl -L -k -O https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
    mv dlc.dat geosite.dat
    curl -L -k -O https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
	cat >/etc/systemd/system/xray.service <<-EOF
		[Unit]
		Description=Xray Service
		Documentation=https://github.com/XTLS/Xray-core
		After=network.target nss-lookup.target
		
		[Service]
		User=root
		#User=nobody
		#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		NoNewPrivileges=true
		ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
		Restart=on-failure
		RestartPreventExitStatus=23
		
		[Install]
		WantedBy=multi-user.target
	EOF
    systemctl daemon-reload
    systemctl enable xray.service

    echo ""
    yellow "装完了(确信)"
}

install_official() {
    update_system
    echo ""
    read -p "是否手动指定 Xray 版本?不指定将安装最新稳定版(y/N): " ownVersion
    if [[ "$ownVersion" == "y" ]]; then
        # 也许根本不需要读取？毕竟不给版本号，官方脚本也会报错
        read -p "请输入安装版本(不要以"v"开头): " xrayVersion
        [[ -z "xrayVersion" ]] && red "请输入有效版本号！" && exit 1
        bash -c "$(curl -L -k https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version ${xrayVersion} -u root
    else
        bash -c "$(curl -L -k https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
    fi
}

update_system() {
    ${PACKAGE_UPDATE[int]}
    ${PACKAGE_INSTALL[int]} curl wget tar openssl lsof
}

get_cert() {
    bash <(curl -L -k https://github.com/tdjnodj/simple-acme/releases/latest/download/simple-acme.sh)
}

install_go() {
    ${PACKAGE_INSTALL[int]} git curl
    # CPU
    bit=`uname -m`
    if [[ $bit = x86_64 ]]; then
        cpu=amd64
    elif [[ $bit = amd64 ]]; then
        cpu=amd64
    elif [[ $bit = aarch64 ]]; then
        cpu=arm64
    elif [[ $bit = armv8 ]]; then
        cpu=arm64
    elif [[ $bit = armv7 ]]; then
        cpu=arm64
    elif [[ $bit = s390x ]]; then
        cpu=s390x
    else 
        cpu=$bit
        red "可能不支持该型号( $cpu )的CPU!"
    fi
    go_version=$(curl https://go.dev/VERSION?m=text)
    red "当前最新版本golang: $go_version"
    curl -O -k -L https://go.dev/dl/${go_version}.linux-${cpu}.tar.gz
    yellow "正在解压......"
    tar -xf go*.linux-${cpu}.tar.gz -C /usr/local/
    sleep 3
    export PATH=\$PATH:/usr/local/go/bin
    rm go*.tar.gz
    echo 'export PATH=\$PATH:/usr/local/go/bin' >> /root/.bash_profile
    source /root/.bash_profile
    yellow "检查当前golang版本: "
    go version
    yellow "为确保正常安装，请手动输入: "
    echo "echo 'export PATH=\$PATH:/usr/local/go/bin' >> /root/.bash_profile"
    red "source /root/.bash_profile"
    echo ""
    echo "如果错误，常见错误原因: 未删除旧的go"
}

unintstall_xray() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
}

updateGEO() {
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata
}

getUUID() {
    echo ""
    uuid_regex='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
    yellow "请输入你的 uuid，如果输入内容不合法将自动映射为一个uuid"
    read -p " " answer
    if [ -z "$answer" ]; then
        uuid=$(uuidgen)
    elif [ "$answer" == "${uuid_regex}" ]; then
        uuid="${answer}"
    else
        red "uuid 不合法！已自动映射！"
        uuid=$(xray uuid -i "$answer")
    fi
}

myHelp() {
    echo ""
    yellow "bash ${PWD}/${0} [选项]"
    echo ""
    yellow "选项:"
    echo ""
    yellow "menu         打开菜单"
    yellow "help         查看本帮助"
    yellow "install      使用官方脚本 安装/更新 xray"
    yellow "build        编译安装 xray"
    yellow "cert         获取 tls 证书"
}

menu() {
    clear
    red " Xray一键安装/配置脚本"
    echo ""
    yellow " 1. 通过官方脚本 安装/更新 Xray"
    yellow " 2. 编译安装 Xray"
    echo ""
    echo " ------------------------------------"
    echo ""
    yellow " 3. 配置 Xray: 无TLS的协议"
    green " 4. 配置 Xray: VLESS + xtls + web (推荐)"
    green " 5. 配置 Xray: 用 REALITY \"借用\" 别人的证书: VLESS + tcp + xtls / VLESS + h2 + tls 共存！"
    echo ""
    echo " ------------------------------------"
    echo " 11. 启动 Xray"
    echo " 12. 停止 Xray"
    echo " 13. 设置 Xray 开机自启动"
    echo " 14. 取消 Xray 开机自启动"
    echo " 15. 查看 Xray 运行状态"
    red " 16. 卸载 Xray"
    echo " 17. 更新 geo 资源文件"
    echo " ------------------------------------"
    echo ""
    yellow " 100. 更新系统和安装依赖"
    yellow " 101. 申请TLS证书(http申请/自签)"
    yellow " 102. 安装最新版本的golang 及 编译 Xray 的其他组件"
    echo ""
    echo " ------------------------------------"
    echo ""
    yellow " 0. 退出脚本"
    read -p "清选择: " answer
    case $answer in
        0) exit 0 ;;
        1) install_official ;;
        2) install_build ;;
        3) set_withoutTLS ;;
        4) set_withXTLS ;;
        5) set_REALITY_steal ;;
        11) systemctl start xray ;;
        12) systemctl stop xray ;;
        13) systemctl enable xray ;;
        14) systemctl disable xray ;;
        15) systemctl status xray ;;
        16) unintstall_xray ;;
        17) updateGEO ;;
        100) update_system ;;
        101) get_cert ;;
        102) install_go ;;
        *) red "不存在本选项！" && exit 1 ;;
    esac
}

action=$1
[[ -z $1 ]] && action=menu

case "$action" in
    menu) menu ;;
    help) myHelp;;
    install) install_official ;;
    build) install_build ;;
    cert) get_cert ;;
    *) red "不存在的选项！" && myHelp ;;
esac
