#! /bin/bash

# Tested
# Plan
# Add support to csv

declare -a Sites 
declare Ipv6_Mode Client_Address

ProcessArgs(){
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h)
                PrintHelp
                exit 0 ;;
            -c)
                Client_Address=$2
                shift 2 ;;
            -6)
                Ipv6_Mode=1 
                shift ;;
            *)
                Sites+=("$1") 
                shift ;;
        esac
    done
}

Main(){
    ProcessArgs "$@"    
    [[ ${#Sites[@]} -eq 0 ]] && { echo "ERROR: No site provided. "; exit 1; }
    [[ $Ipv6_Mode ]] && echo "Using IPv6 only mode..." || echo "Using IPv4 only mode (use argument \"-6\" for IPv6 mode)..."
	[[ ! $Client_Address ]] && echo "Client webiste not provided. Use argument \`-c domestic_ip_or_domain\` to help benchmark latency. "

    local s; for s in "${Sites[@]}"; do
        TestSingleSite "$s"
    done
}

TestSingleSite(){
    local site=$1
    local flag; [[ $Ipv6_Mode ]] && flag="-6" || flag="-4"
    local -A result

    local tmp
    
    echo "Trying to establish TLS handshake with $site..."
    tmp=$(openssl s_client  "$flag"  -connect "$site:443"  -alpn h2,http/1.1 -status </dev/null 2>/dev/null)
    [[ $? -ne 0 ]] && { echo "Cannot handshake with $site. Aborting..."; exit 1; }
    printf "%s" "$tmp" | grep -i -I "TLSv1.3" && result[tls1_3]=1
    printf "%s" "$tmp" | grep -i -I "ALPN protocol: h2" && result[h2]=1
    printf "%s" "$tmp" | grep -i -I "X25519" && result[x25519]=1

    local ocsp_status
    ocsp_status=$(printf "%s" "$tmp" | grep -I "OCSP Response Status")
    echo "$ocsp_status" | grep -iq "successful" && result[ocsp]=1
     
    local status_code
    echo "Trying curl $site web content..."
    tmp=$(curl "$flag" -s -I -w "TCP: %{time_connect}\nSSL: %{time_appconnect}\n" "https://$site")
    status_code=$(cat <<<"$tmp" | head -n 1 | awk '{print $2}'); echo "Status code: $status_code"
    result[handshake_time]=$(cat <<<"$tmp" | tail -n 1 | awk '{print $2 * 1000}')
    [[ $status_code != 3* || $status_code == 307 ]] && result[no_redirect]=1

	echo "Scoring based on result..."
	local score; score=$(Score result)

    echo "Result: "
    PrintResult result
    echo "Final score: $score"
}

PrintResult(){ local -n _dict=$1; cat <<EOF
    Required:
        TLS 1.3: $(CheckSupport "${_dict[tls1_3]}")
        H2: $(CheckSupport "${_dict[h2]}")
        X25519: $(CheckSupport "${_dict[x25519]}")
        No redirection: $(CheckSupport "${_dict[no_redirect]}")
    Elective:
        OCSP: $(CheckSupport "${_dict[ocsp]}")
        Certificate fetch time: ${_dict[handshake_time]}ms
EOF
}

Score(){
    local -n _dict=$1
    [[ ${_dict[tls1_3]} && ${_dict[h2]} && ${_dict[x25519]} && ${_dict[no_redirect]} ]] || { echo 0; return 0; }
    
    local score=50
    local room=$(( 100 - score ))
	local w

    local -A bool_weights=(
        [ocsp]=0.5
    )
    local k; for k in "${!bool_weights[@]}"; do
		if [[ ${_dict[$k]} ]]; then
			w=${bool_weights[$k]}
			score=$(awk "BEGIN { printf \"%.2f\", $score + $room * $w }")
		fi
    done

    local -A numeric_weights=(
        [latency]=0.5
    )
	w=${numeric_weights[latency]}
	local latency_ratio; latency_ratio=$(ScoreLatency "${_dict[handshake_time]}")
    score=$(awk "BEGIN { printf \"%.2f\", $score + $room * $w * $latency_ratio }")

	echo "$score"
}

# Very very very rough model :/
ScoreLatency(){
	echo "Roughly comparing handshake time with ping lantency with client..." >&2
    local handshake_ms=$1
    local ping_ms
    local -A steps=(
        [0.2]=1
        [0.4]=0.75
        [0.8]=0.5
        [1.3]=0.25
    )

	local default_ping_ms=150
    if [[ -n $Client_Address ]]; then
		local tmp; if tmp=$(ping -c 6 -W 1 "$Client_Address"); then
			ping_ms=$(printf "%s" "$tmp" | awk -F'[ /]' '/rtt/ {print $8}')
			echo "Average ping time with $Client_Address is $ping_ms" >&2
		else
			ping_ms=$default_ping_ms
			echo "Failed to ping $Client_Address. Default to $default_ping_ms." >&2
		fi
	else
		ping_ms=$default_ping_ms
		echo "Client address not provided. Default to $default_ping_ms." >&2
    fi

    local ratio; ratio=$(awk "BEGIN { printf \"%.2f\", $handshake_ms / $ping_ms }")

    local s; for s in "${!steps[@]}"; do
        if awk "BEGIN { exit !($ratio <= $s) }"; then
			echo "${steps[$s]}"
			return 0
		fi
    done
    echo 0
}

CheckSupport(){
    [[ $1 ]] && echo "Supported" || echo "Failed"
}

PrintHelp(){ cat <<EOF
Usage:
    -6
        Test IPv6
    -t 
        Domestic address to benchmark TLS handshake time
    SITE
        Space-separated sites

Example:
    bash this_script.sh -6 -t example.cn www.example.com download.example.com
EOF
}

Main "$@"