#! /bin/bash

# Finished
# Plan
# Add support to csv

declare -a Sites 
declare Ipv6_Mode Domestic_Address

ProcessArgs(){
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h)
                PrintHelp
                exit 0 ;;
            -t)
                Domestic_Address=$2
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

    local s; for s in "${Sites[@]}"; do
        TestSingleSite "$s"
    done
}

TestSingleSite(){
    local site=$1
    local flag; [[ $Ipv6_Mode ]] && flag="-6" || flag="-4"
    local -A result

    local tmp
    
    echo "Trying to establish TLS hanshake with $site..."
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
    result[hanshake_time]=$(cat <<<"$tmp" | tail -n 1 | awk '{print $2 * 1000}')
    [[ $status_code != 3* || $status_code == 307 ]] && result[no_redirect]=1

    echo "Result: "
    PrintResult result
    echo "Final score: $(Score result)"
}

PrintResult(){ local -n _dict=$1; cat <<EOF
    Required:
        TLS 1.3: $(CheckSupport "${_dict[tls1_3]}")
        H2: $(CheckSupport "${_dict[h2]}")
        X25519: $(CheckSupport "${_dict[x25519]}")
        No redirection: $(CheckSupport "${_dict[no_redirect]}")
    Elective:
        OCSP: $(CheckSupport "${_dict[ocsp]}")
        Certificate fetch time: ${_dict[hanshake_time]}ms
EOF
}

Score(){
    local -n _dict=$1
    [[ ${_dict[tls1_3]} && ${_dict[h2]} && ${_dict[x25519]} && ${_dict[no_redirect]} ]] || { echo 0; return 0; }
    
    local score=60
    local room=$(( 100 - score ))

    local -A bool_weights=(
        [ocsp]=0.5
    )
    local w; for w in "${!bool_weights[@]}"; do
        [[ ${_dict[$w]_1} ]] && score+=$(( room * ${bool_weights[$w]}   ))
    done

    local -A numeric_weights=(
        [latency]=0.5
    )
    score+=$(( room * numeric_weights[latency] / $(ScoreLatency "${_dict[hanshake_time]}") ))
    
    echo "$score"
}

ScoreLatency(){
    local handshake_ms=$1
    local ping_ms
    local -A steps=(
        [0.7]=100
        [1.8]=75
        [3.5]=50
        [6]=25
    )

    local tmp; if [[ -n $Domestic_Address ]] && tmp=$(ping -c 6 -W 1 "$Domestic_Address"); then
        ping_ms=$(printf "%s" "$tmp" | awk -F'[ /]' '/rtt/ {print $8}')
    fi
    [[ -z $base ]] && base=150

    local ratio; ratio=$(echo "scale=3; $handshake_ms / $ping_ms" | bc)

    local s; for s in "${!steps[@]}"; do
        (( ratio <= s )) && { echo "${steps[$s]}" ; return 0; }
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