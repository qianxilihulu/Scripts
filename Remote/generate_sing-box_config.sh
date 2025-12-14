#! /bin/bash

set -e -o pipefail

Dir="$(pwd)"
declare -a Inbounds ClientOubounds
declare Dns_Strategy

Default_Tag="Don't forget to tag"

Main(){
    command -v sing-box >/dev/null && printf "sing-box installation detected.\n\n" || { echo "[!] No sing-box installation found."; exit 1; }
    local answer

    read -rp "Set up Vless inbound? [y/n]: " answer
    CheckYesNo "$answer" && SetUpVless && InstallTcpBrutal
    echo

    read -rp "Set up ShadowSocks inbound? [y/n]: " answer
    CheckYesNo "$answer" && SetUpShadowSocks
    echo

    [[ ${#Inbounds[@]} -eq 0 ]] && { echo "No inbounds defined. Aborting..."; exit 1; }

    GetDnsStrategy
    echo

    local tmp; tmp=$(mktemp) || { echo "mktemp failed"; exit 1; }
    ServerConfig > "$tmp"
    SingBoxFormat "$tmp"
    
    local output_file="$Dir/sing-box.json"
    cp "$tmp" "$output_file"
    echo "Saved result to $output_file"
    echo

    echo "Client configuration:"
    ClientConfig > "$tmp"
    SingBoxFormat "$tmp"
    cat "$tmp"
}

SetUpVless(){
    echo "Setting up Vless..."
    local port short_id public_key private_key reality_server server
    local -a users
    local answer

    read -rp "Port Vless serves on [Default: 443]: " answer
    answer=$(Trim "${answer}")
    port=${answer:-443}

    local -A user
    user[name]="vless_client"
    user[uuid]=$(sing-box generate uuid)
    users+=("$(ConvertAssociatedArrayToObject user)")

    read -rp "Reality camouflage server [Example: itunes.apple.com]: " answer
    reality_server=$(Trim "$answer")
    [[ -z "$reality_server" ]] && { echo "[!] No server provided. Aborting..."; exit 1; }
    
    local key_pair; key_pair=$(sing-box generate reality-keypair)
    public_key=$(printf "%s" "$key_pair" | awk -F': ' '/PublicKey/ {print $2}')
    private_key=$(printf "%s" "$key_pair" | awk -F': ' '/PrivateKey/ {print $2}')

    short_id=$(sing-box generate rand 4 --hex)

    local -a servers
    echo "Choose the public IP client to connect to:"
    ChoosePublicIp servers

    local -A dict=(
        [port]=$port
        [uuid]=${user[uuid]}
        [reality_server]=$reality_server
        [reality_public_key]=$public_key
        [reality_private_key]=$private_key
        [reality_short_id]=$short_id
		[client_tag]="$RANDOM $Default_Tag"
    )
    Inbounds+=("$(VlessInbound dict users)")
    local s; for s in "${servers[@]}"; do
        dict[server]=$s
        ClientOubounds+=("$(ClientVlessOutbound dict)")
    done
}

SetUpShadowSocks(){
    echo "Setting up ShadowSocks..."
    local -A available_methods=( 
        [1]="2022-blake3-aes-128-gcm" 
        [2]="2022-blake3-aes-256-gcm"
        [3]="2022-blake3-chacha20-poly1305"
    )
    local -A key_length_requirements=(
        [2022-blake3-aes-128-gcm]=16
        [2022-blake3-aes-256-gcm]=32
        [2022-blake3-chacha20-poly1305]=32
    )
    local port method server_password
    local -a users
    local answer

    read -rp "Port ShadowSocks serves on [Default: Randomized between 49152 and 65535]: " answer
    answer=$(Trim "${answer}")
    port=${answer:-$(( RANDOM % 16383 + 49152 ))}

    if lscpu | grep -iq aes; then
        echo "Hardware supports AES-NI."
        method="2022-blake3-aes-128-gcm"
    else
        echo "No hardware AES-NI support."
        method="2022-blake3-chacha20-poly1305"
    fi

    server_password=$(sing-box generate rand --base64 "${key_length_requirements[$method]}")

    local -A user
    user[name]="ss_client"
    user[password]=$(sing-box generate rand --base64 "${key_length_requirements[$method]}")
    users+=("$(ConvertAssociatedArrayToObject user)")

    local -a servers
    echo "Choose the public IP client to connect to:"
    ChoosePublicIp servers

    local -A dict=(
        [server]=$server
        [port]=$port
        [method]=$method
        [server_password]=$server_password
        [user_password]=${user[password]}
		[client_tag]="$RANDOM $Default_Tag"
    )
    Inbounds+=("$(ShadowSocksInbound dict users)")
    local s; for s in "${servers[@]}"; do
        dict[server]=$s
        ClientOubounds+=("$(ClientShadowSocksOutbound dict)")
    done
}

InstallTcpBrutal(){
	echo "Installing TCP Brutal kernel module..."
	bash <(curl -fsSL https://tcp.hy2.sh/)
}

GetDnsStrategy(){
    echo "Choosing server side resolving strategy..."
    echo "Note this only affects server-originated DNS queries, e.g., resolving rule-set or Reality domains."
    local -a options=(both prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only )

    Dns_Strategy=$(PickFromArray "${options[@]}")
    [[ $Dns_Strategy == "both" ]] && Dns_Strategy="" || return 0
}

ChoosePublicIp(){
    local -n _addrs=$1

    local info; local -a list
    echo "Detecting available public addresses..." >&2
    info=$( ip addr show scope global \
      | grep -oP '(?<=inet6 )[0-9a-f:]+|(?<=inet )([0-9]+\.){3}[0-9]+' \
      | grep -Pv '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|127\.|f|::1$)'
    )
    readarray -t list < <(printf "%s\n" "$info" | sort -u)
    local custom="Custom domain or IP that points to this server"; list+=("$custom")

    PickFromArray -m _addrs "${list[@]}"

    local choice
    local i count; count=${#_addrs[@]}
    for (( i=0; i<count; i++ )); do
        [[ "${_addrs[$i]}" != "$custom" ]] && continue
        local answer customs
        read -rp "Type your custom domain or IP (Allow multiple seprated by blank space): " answer
        readarray -t customs < <(echo "$answer" | xargs -n1 | sort -u)
        _addrs+=("${customs[@]}")
        unset "_addrs[$i]"
    done
    
    local choice; for choice in "${_addrs[@]}"; do
        [[ "$choice" != "$custom" ]] && continue
        local answer customs
        read -rp "Type your custom domain or IP (Allow multiple seprated by blank space): " answer
        readarray -t customs < <(echo "$answer" | xargs -n1 | sort -u)
        _addrs+=("${customs[@]}")
    done
}

ServerConfig(){ cat <<EOF
    {
        $(ConvertArrayToJsonField Inbounds inbounds),

        "route": {
            "rules": [
                {
                    "domain_suffix": ".cn",
                    "action": "reject"
                },
                {
                    "rule_set": [ "geoip-cn" ],
                    "action": "reject"
                },
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        { "rule_set": [ "geosite-cn" ] },
                        { "invert": true, "rule_set": [ "geosite-geolocation-!cn" ] }
                    ],
                    "action": "reject"
                }
            ],
            "rule_set": [
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
                },
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
                },
                {
                    "tag": "geosite-geolocation-!cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs"
                }
            ]
        },

        "outbounds": [ 
            { $(DirectOutbound) } 
        ],

        "dns": {
            $( [[ -n $Dns_Strategy ]] && echo "\"strategy\": \"$Dns_Strategy\"", )
            "servers": [
                { $(LocalDns) }
            ]
        },

        "log": {
            "disabled": false,
            "level": "debug"
        }
    }
EOF
}

ClientConfig(){ cat <<EOF
    {
        $(ConvertArrayToJsonField ClientOubounds outbounds)
    }
EOF
}

VlessInbound(){ local -n _dict=$1 _users=$2; cat <<EOF
    "tag": "vless-in",
    "type": "vless",
    "listen": "::",
    "listen_port": ${_dict[port]},
    "users": $(ConvertArrayToJsonArray _users),
    "tls": {
        "enabled": true,
        "server_name": "${_dict[reality_server]}",
        "reality": {
            "enabled": true,
            "handshake": {
                "server": "${_dict[reality_server]}",
                "server_port": 443
            },
            "private_key": "${_dict[reality_private_key]}",
            "short_id":  "${_dict[reality_short_id]}" ,
            "max_time_difference": "1m"
        }
    },
	"multiplex": {
		"enabled": true,
        "padding": true,
		"brutal": {
			"enabled": true,
			"up_mbps": 25,
			"down_mbps": 25
		}
	}
EOF
}

ShadowSocksInbound(){ local -n _dict=$1 _users=$2; cat <<EOF
    "tag": "ss-in",
    "type": "shadowsocks",
    "listen": "::",
    "listen_port": ${_dict[port]},
    "method": "${_dict[method]}",
    "password": "${_dict[server_password]}",
    "users": $(ConvertArrayToJsonArray _users),
	"multiplex": { 
		"enabled": true
	}
EOF
}

# Vision conflicts with multiplex
ClientVlessOutbound(){ local -n _dict=$1; cat <<EOF
    "tag": "${_dict[client_tag]}",
    "type": "vless",
    "server": "${_dict[server]}",
    "server_port": ${_dict[port]},
    "uuid": "${_dict[uuid]}",
    "tls": {
        "enabled": true,
        "server_name": "${_dict[reality_server]}",
        "reality": {
            "enabled": true,
            "public_key": "${_dict[reality_public_key]}",
            "short_id": "${_dict[reality_short_id]}"
        },
        "utls": {
            "enabled": true,
            "fingerprint": "chrome"
        }
    },
	"multiplex": {
		"enabled": true,
		"padding": true,
		"protocol": "h2mux",
		"max_connections": 3,
        "min_streams": 6,
		"brutal": {
			"enabled": true,
			"up_mbps": 25,
			"down_mbps": 25
		}
	}
EOF
}

# smux and yamux uses heartbeat packets to keep alive, and may aggressively kill connections in high RTT scenarios.
ClientShadowSocksOutbound(){ local -n _dict=$1; cat <<EOF
    "tag": "${dict[client_tag]}",
    "type": "shadowsocks",
    "server": "${_dict[server]}",
    "server_port": ${_dict[port]},
    "method": "${_dict[method]}",
    "password": "${_dict[server_password]}:${_dict[user_password]}",
	"multiplex": { 
		"enabled": true, 
		"protocol": "h2mux",
		"max_connections": 2,
		"min_streams": 16
	},
    "detour": "Using ShadowSocks directly in mainland China may receive immediate block by GFW"
EOF
}

DirectOutbound(){ cat <<EOF
    "tag": "direct-out",
    "type": "direct"
EOF
}

LocalDns(){ cat <<EOF
    "tag": "local_dns",
    "type": "local"
EOF
}

SingBoxFormat(){
	local msg file=$1
	if msg=$(sing-box format -w -c "$file" 2>&1); then
		return 0
	else
		printf 'Sing-Box format error: %s\n' "$msg"
		return 1
	fi
}

ConvertArrayToJsonField(){
    local -n _arr=$1
    local name=$2
    [[ ${#_arr[@]} -eq 0 ]] && return 0
    echo "\"$name\": $(ConvertArrayToJsonArray _arr)"
}

ConvertArrayToJsonArray(){
    local -n __arr=$1
    
    local result="[" value
    local i count=${#__arr[@]}
    for (( i=0; i<count; i++ )); do
        value=${__arr[i]}
        [[ $value != "["* && $value != "{"* ]] && value="{$value}"
        result+="$value"
        (( i != count-1 )) && result+=","
    done
    result+="]"

    echo "$result"
}

ConvertAssociatedArrayToObject(){
    local -n __arr=$1

    local is_first result="{"
    local key value
    for key in "${!__arr[@]}"; do
        value=${__arr[$key]}
        [[ $value != "["* && $value != "{"* ]] && value="\"$value\""
        [[ $is_first ]] && result+=", "
        result+="\"$key\": $value"
        is_first=1
    done
    result+="}"

    echo "$result"
}

Trim(){
    echo "$1" | sed -E 's/^\s+//;s/\s+$//'
}

CheckYesNo() {
    local input=$1
    [[ -z $input ]] && input=$2 # Default value

   if [[ $input =~ ^[:space:]*[Yy].* ]]; then
        return 0
    elif [[ $input =~ ^[:space:]*[Nn].* ]]; then
        return 1
    else 
        echo "Unknown Input. Please type Y or y or N or n."
        exit 1
    fi
}

PickFromArray(){
    local multiple; 
    [[ $1 == -m ]] && { multiple=1; local -n _arr=$2; shift 2; }
    
    local -a list=("$@")
    local count; count=${#list[@]}
    for(( i=1; i<=count; i++ )); do
        echo "$i. ${list[i-1]}" >& 2
    done

    local answer; read -rp "Choose by index$( [[ $multiple ]] && echo " (Allow multiple seprated by blankspace)"): " answer
    
    validate_input(){
        [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 && $1 <= $2 )) || { echo "Invalid input. Aborting..." >& 2; exit 1; }
    }
    if [[ $multiple ]]; then
        local choices; readarray -t choices < <(echo "$answer" | xargs -n1 | sort -u)
        local c; for c in "${choices[@]}"; do
            validate_input "$c" "$count"
            _arr+=("${list[$((c - 1))]}")
        done
    else
        answer=$(Trim "$answer")
        validate_input "$answer" "$count"
        echo "${list[$((answer - 1))]}"
    fi
}

Main