#! /bin/bash

Dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare Host User Port Key Socket
declare Interface Prefix
declare -A Addresses

declare -A Test_Set
declare Count
declare Winner_Ip

Result_Record=$(mktemp)

Main(){
    CheckLocalIperf
    echo
    InitializeInformation "$@"
    echo
    CreateMasterConnection
    trap CleanUp EXIT
    echo
    CheckServerIperf
    echo
    GetServerIpv6
    echo
    GetTestCount
    echo
    StartServerIperf
    echo
    CheckServerIperfReachable
    echo
    GenerateRandomIp
    echo
    RunTest
    echo
    Rank
    echo
}

InitializeInformation(){
    local host user port key

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--host)
                host="$2"; shift 2 ;;
            -u|--user)
                user="$2"; shift 2 ;;
            -p|--port)
                port="$2"; shift 2 ;;
            -k|--key)
                key="$2"; shift 2 ;;
            *)
                echo "Unknown option: $1"; exit 1 ;;
        esac
    done

    [[ -z $host ]] && read -rp "SSH server hostname or IP: " host
    [[ -z $user ]] && read -rp "SSH username [default root]: " user
    [[ -z $port ]] && read -rp "SSH port [default 22]: " port
    [[ -z $key ]] && read -rp "SSH key absoulte path, return if using keys under ~/.ssh/config or password: " key
    
    Host=$(Trim "$host")
    User=$(Trim "${user:-root}")
    Port=$(Trim "${port:-22}")
    [[ -n $key ]] && Key=$(Trim "$key")
}

CreateMasterConnection(){
    echo "Creating master SSH connection..."
    local key_option; [[ -n "$Key" ]] && key_option="-i $Key"

    Socket="/tmp/$User@$Host:$Port.sock"
    eval "ssh -f -M -o ControlPath=$Socket -o ControlPersist=yes $key_option -p $Port $User@$Host sleep 1"
    echo "Master SSH connection created at $Socket"
}

CheckLocalIperf(){
    echo "Checking if iperf3 is installed locally..."
    if command -v iperf3 >/dev/null 2>&1; then
        echo "Local iperf3 found."
    else
        echo "[!] Local iperf3 not found."
        echo "Please install it from a new terminal before proceeding."
        read -rp "Return after installation completed: "
        command -v iperf3 >/dev/null 2>&1 || { echo "[!] iperf still not found locally. Aborting..."; exit 1; }
    fi
}

CheckServerIperf(){
    echo "Checking if iperf3 is installed on remote server..."

    if SshRunCommand "command -v iperf3 >/dev/null 2>&1"; then
        echo "iperf3 found on remote server."
    else
        echo "[!] iperf3 not found on remote server."
        echo "Please install before proceeding."
        echo "You'll enter a SSH session for manual installation. Use command \`exit\` after installation completed."
        EnterSsh
        SshRunCommand "command -v iperf3 >/dev/null 2>&1" || { echo "[!] iperf still not found on remote server. Aborting..."; exit 1; }
    fi
}

GetServerIpv6(){
    echo "Detecting local IPv6 default interface and prefix..."
    local tmp interface address prefix 
    local -a interfaces addresses
    local count

    tmp=$(SshRunCommand "ip -o -6 addr show scope global | grep -v \"inet6 f\" | awk '{print \$2}'")
    readarray -t interfaces < <(printf "%s\n" "$tmp" | sort -u)
    count=${#interfaces[@]}
    if (( count == 1 )); then
        interface=${interfaces[0]}
        echo "Detected interface: $interface"
    elif (( count == 0 )); then
        echo "[!] Could not detect default IPv6 interface via routing table."
        read -rp "Please enter interface name manually (e.g., eth0): " interface
        interface=$(Trim "$interface")
    elif (( count > 1)); then
        echo "Detected multiple interfaces with public IPv6 address."
        interface=$(PickFromArray "${interfaces[@]}")
        echo "Using interface $interface"
    fi
    
    tmp=$(SshRunCommand "ip -6 addr show scope global | grep -v \"inet6 f\" | grep -oP 'inet6 \\K[0-9a-f:]+'")
    readarray -t addresses < <(printf "%s\n" "$tmp" | sort -u)
    count=${#addresses[@]}
    if (( count == 1 )); then
        address=${addresses[0]}
        echo "Detected IPv6 address: $address"
    elif (( count == 0 )); then
        echo "[!] No global IPv6 address found on interface $Interface."
        read -rp "Please enter an example public IPv6 address manually: " address
        address=$(Trim "$address")
    elif (( count > 1)); then
        echo "Detected multiple public IPv6 addresses."
        address=$(PickFromArray "${addresses[@]}")
        echo "Using address $address"
    fi
    ConvertArrayToAssociated Addresses "${addresses[@]}"
    
    prefix=$(echo "$address" | awk -F':' '{print $1":"$2":"$3":"$4}')
    echo "Prefix: $prefix"

    Interface=$interface
    Prefix=$prefix
}

GetTestCount(){
    local count first_time=0
    while ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -le 0 ]; do
        [[ $first_time -ne 0 ]] && { echo "[!] Invalid number."; echo "Let's try again."; }
        read -rp "How many IPv6 addresses to test? [default 10]: " count
        count=$(Trim "${count:-10}") 
        first_time=1
    done

    Count=$count
}

StartServerIperf(){
    echo "Starting iperf3 server on remote host..."
    
    if SshRunCommand "nohup iperf3 -s > /dev/null 2>&1 &" && { sleep 2;  echo -n "iperf3 server should be running as pid: "; SshRunCommand "pgrep iperf3"; }; then
        :
    else
        echo "[!] Failed to start iperf3 remotely. Aborting..."
        exit 1
    fi
}

CheckServerIperfReachable() {
    echo "Checking the reachability to $Host:5201..."

    if CheckPortOpen $Host 5201; then
        echo "Port 5201 appears reachable."
    else
        echo "[!] Port 5201 seems to be BLOCKED."
        echo "Probably a firewall issue."
        echo "You'll enter a SSH session to manually allow TCP connection to port 5201 using your server distro's default firewall tool. Use command \`exit\` if completed."
        EnterSsh
        CheckPortOpen $Host 5201 || { echo "[!] Port 5201 seems still to be BLOCKED. Aborting..."; exit 1; }
    fi
}

GenerateRandomIp(){
    echo "Generating $Count IPv6 addresses in $Prefix::/64 and adding them to $Interface..."
    local i=0; declare -A generated 
    
    while [[ $i -lt $Count ]]; do
        ip="$Prefix:$(GenereateRandomIpAffix)"

        if ! [[ ${generated[$ip]+_} || ${Addresses[$ip]+_} ]]; then
            generated["$ip"]=1
            (( i++ ))
        fi
    done

    echo "Adding generated IPv6 addresses to the interface $Interface... This will prompt password for sudo priviledge."
    AddTestIp "${!generated[@]}"

    ConvertArrayToAssociated Test_Set "${!generated[@]}"
}

RunTest(){
    echo "Running iperf3 download tests for each IPv6 addresses..."
    local duration test_set ip result line value unit rate

    local first_time=0
    while [[ ! $duration =~ ^[1-9][0-9]*$ ]]; do
        [[ $first_time -gt 0 ]] && echo "Invalid input. Let's try again."
        read -rp "How much duration should each test take, in seconds? [Default 10]: " duration
        duration=$(Trim "${duration:-10}")
        first_time=1
    done

    local answer
    read -rp "Test original IPv6 addresses as well? Takes more time but good for benchmarking. Type anything for yes, return for no: " answer
    [[ -n $answer ]] && CopyArrayToArray test_set "${!Addresses[@]}"
    echo

    CopyArrayToArray test_set "${!Test_Set[@]}"
    for ip in "${test_set[@]}"; do
        echo "Testing for $ip"

        CheckPortOpen $Host 5201 && echo "$ip reacheable." || { echo "[!] $ip not reachable. Skipping..."; echo; continue; }

        result=$(IperfIp "$ip" "$duration") # timeout as fail-safe # redirect to tty for better interactivity
        line=$(echo "$result" | awk '/sender/ {print $(NF-3), $(NF-2)}')
        echo "Result for $ip: $line"
        echo

        read -r value unit <<< "$(echo "$line" | xargs)"
        rate=$(awk -v value="$value" -v unit="$unit" '
            BEGIN {
                f = 1;
                if (unit ~ /^K/) f = 1e3;
                else if (unit ~ /^M/) f = 1e6;
                else if (unit ~ /^G/) f = 1e9;
                printf "%.0f", value * f;
            }')
        echo "$ip $rate" >> "$Result_Record"
    done
}

Rank(){
    echo "Ranking test results..."
    [[ ! -s "$Result_Record" ]] && { echo "[!] No successful iperf3 results."; exit 1; }
    
    local sorted_result="/tmp/${Host}_iperf3_ipv6_results_$$.txt"
    sort -k2 -n -r "$Result_Record" | tee "$sorted_result"
    echo "Sorted results saved to: $sorted_result"
    echo

    local line ip rate
    line=$(sort -k2 -n -r "$Result_Record" | head -n 1)
    ip=$(echo "$line" | awk '{print $1}')
    rate=$(echo "$line" | awk '{print $2/1e6}')
    printf "Winner: %s\n" "$ip"
    printf "Rate: %s\n" "$rate Mbps"
    echo "From $( [[ ${Addresses[$ip]+_} ]] && echo "original" || echo "test" ) addresses"

    Winner_Ip=$ip
}

CleanUp() {
    echo "Cleaning up..."
   
    if [[ -n "$Winner_Ip" && -z "${Addresses["$Winner_Ip"]+_}" ]]; then
        local answer
        read -rp "Keep the winner address? Type anything for yes, return for no: " answer
        [[ -n $answer ]] && unset "Test_Set[$Winner_Ip]"
    fi

    if (( ${#Test_Set[@]} != 0 )); then
        DeleteTestIp "${!Test_Set[@]}"
        echo "Deleted all test IPv6 addresses."
    fi

    SshRunCommand "pkill iperf3"
    echo "Stopped iperf3 process."

    rm "$Socket"
    echo "Master SSH connection socket removed."
}

AddTestIp(){
    SshTtyRunCommand "$(GenerateAddOrDeleteIpCommand "add" "$@")"
}

DeleteTestIp(){
    SshTtyRunCommand "$(GenerateAddOrDeleteIpCommand "del" "$@")"
}

IperfIp(){
    local i ip=$1 duration=$2
    for((i=0; i<3; i++)); do
        timeout $(( duration + 3 )) stdbuf -oL iperf3 -6 -R -c "$ip" -t "$duration" 2>&1 | tee /dev/tty && return 0 || echo "Attempt $i: Failed to run iperf3 for $ip."
    done
    return 1
}

GenerateAddOrDeleteIpCommand(){
    local command=$1 result; shift
    [[ $command != "add" && $command != "del" ]] && { echo "[BUG] No command provided. Use [ add | del ]."; exit 1; }
    
    for ip in "$@"; do
        result+="ip addr $command $ip/64 dev $Interface 2>/dev/null; "
    done
    echo "sudo sh -c \"$result\""
}

GenereateRandomIpAffix(){
    printf '%x:%x:%x:%x' $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536)) $((RANDOM%65536))
}

SshRunCommand(){
    local command="$1"
    ssh -S "$Socket" -p "$Port" "$User@$Host" "$command"
}

SshTtyRunCommand(){
    local command="$1"
    ssh -tt -S "$Socket" -p "$Port" "$User@$Host" "$command"
}

EnterSsh(){
    echo "Entering SSH connection for manual intervention..."
    ssh -S "$Socket" -p "$Port" "$User@$Host"
}

CheckPortOpen(){
    local i host=$1 port=$2
    for((i=0; i<3; i++)); do
        curl -v -6 -m 1 "telnet://[$host]:$port" 2>&1 | grep -iq "established" && return 0 || echo "Attempt $i: Failed to check if port $port of $host is open."
    done
    return 1    
}

PickFromArray(){
    local -a array=("$@")
    local count; count=${#array[@]}

    for((i=0; i<count; i++)); do
        echo "$i. ${array[i]}" >& 2
    done

    local answer; read -rp "Choose by index: " answer
    answer=$(Trim "$answer")

    [[ "$answer" =~ ^[0-9]+$ ]] && (( answer >= 0 && answer < count )) || { echo "Invalid input. Aborting..." >& 2; exit 1; }
    
    echo "${array[$answer]}"
}

ConvertArrayToAssociated(){
    declare -n _ref=$1; shift
    local item
    for item in "$@"; do
        _ref+=("$item")
    done
}

CopyArrayToArray(){
    declare -n _ref=$1; shift
    local item
    for item in "$@"; do
        _ref+=("$item")
    done
}

Trim(){
    echo "$1" | sed -E 's/^\s+//;s/\s+$//'
}

Main "$@"