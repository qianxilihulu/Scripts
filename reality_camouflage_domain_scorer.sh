#! /bin/bash

Script_Name=$(basename "$0")

declare Site Ipv6_Mode

ProcessArgs(){
    local arg
    for arg in "$@"; do
        case "$arg" in
            -6)
                Ipv6_Mode=1 ;;
            *)
                [[ -z $Site ]] && Site=$arg || { echo "Unknown argument: $arg"; exit 1; } ;;
        esac
    done
}

Main(){
    ProcessArgs "$@"    
    [[ -z $Site ]] && { echo "Error: No site provided. Example usage: bash $Script_Name example.com"; exit 1; }
    local flag; [[ $Ipv6_Mode ]] && { echo "Using IPv6 only mode..."; flag="-6"; } || { echo "Using IPv4 only mode (use argument \"-6\" for IPv6 mode)..."; flag="-4"; }
    local output
    local -A dict
    
    echo "Trying to establish TLS hanshake with $Site..."
    output=$(openssl s_client  "$flag"  -connect "$Site:443"  -alpn h2,http/1.1 -status </dev/null 2>/dev/null)
    [[ $? -ne 0 ]] && { echo "Cannot handshake with $Site. Aborting..."; exit 1; }
    printf "%s" "$output" | grep -i -I "TLSv1.3" && dict[tls1_3]=1
    printf "%s" "$output" | grep -i -I "ALPN protocol: h2" && dict[h2]=1
    printf "%s" "$output" | grep -i -I "X25519" && dict[x25519]=1

    local ocsp_status
    ocsp_status=$(printf "%s" "$output" | grep -I "OCSP Response Status")
    echo "$ocsp_status" | grep -iq "successful" && dict[ocsp]=1
    echo
     
    local status_code
    echo "Trying curl $Site web content..."
    output=$(curl "$flag" -s -I -w "TCP: %{time_connect}\nSSL: %{time_appconnect}\n" "https://$Site")
    status_code=$(cat <<<"$output" | head -n 1 | awk '{print $2}'); echo "Status code: $status_code"
    dict[hanshake_time]=$(cat <<<"$output" | tail -n 1 | awk '{print $2 * 1000}')
    [[ $status_code != 3* || $status_code == 307 ]] && dict[no_redirect]=1
    echo

    echo "Result:"
    PrintResult dict
}

PrintResult(){ local -n _dict=$1; cat <<EOF
    Required:
        TLS 1.3: $(CheckSupport "${_dict[tls1_3]}")
        H2: $(CheckSupport "${dict[h2]}")
        X25519: $(CheckSupport "${dict[x25519]}")
        No redirection: $(CheckSupport "${dict[no_redirect]}")
    Elective:
        OCSP: $(CheckSupport "${dict[ocsp]}")
        Certificate fetch time: ${dict[hanshake_time]}ms
EOF
}

Score(){
    local -n _dict=$1
    [[ ${_dict[tls1_3]_1} && ${dict[h2]_1} && ${dict[x25519]_1} && ${dict[no_redirect]_1} ]] || { echo 0; return 0; }
    local score=60

    local -A weights=(
        [ocsp]=0.5
        [latency]=0.5
    )
    local room=$(( 100 - score ))
    local key; for key in "${!weights[@]}"; do
        [[ ${dict[$key]_1} ]] && score+=$(( room * ${weights[$key]}   ))
    done
    
    echo "$score"
}

CheckSupport(){
    [[ $1 ]] && echo "Support" || echo "Failed"
}

Main "$@"