#! /bin/bash

# Unfinished
# /etc/ssh/sshd_config.d/ not considered
# Restore not updated
# Timestamp

InitializeShared(){
    # Color code
    R=$'\e[0;31m'
    G=$'\e[0;32m'
    B=$'\e[0;34m'
    Y=$'\e[0;33m'
    I=$'\e[0m' # Reset/Init
    
    # Log code
    Sudoers_Modified="Sudoers file modified"
    Hostname_Modified="Hostname changed from: "
    Ssh_Config_Backed_Up="ssh_config backed up"
    Root_Password_Modified="Root user password changed"
    Fail2ban_Installed="Fail2Ban installed"
    Ufw_Installed="ufw installed"
    Nftables_Installed="Nftables installed"
    Nftables_Rule_Modified="Nftables rules added"
    Private_Keys_Fetched="Private keys fetched"
    Private_Keys_Added="Private keys added to /etc/.ssh/config/ with timestamp: "
    Restore_Files_Fetched="Restoration files fetched"
    Public_Key_Added="All public key added"
    Package_Updating="Initiated updating for all packages"
    Package_Updated="All packages updated"
    Hosts_File_Modified="/etc/hosts modified"
    
    CheckIfSudo(){
        if [[ "$EUID" -ne 0 ]]; then
            echo -e "${R}ERROR${I}: This script requires root privileges. Please log into the server as root user."
            exit 1
        fi
    }
    
    CheckIfTyping(){
        local answer
        read -rp "Do you wish to enable ${Y}typing effect${I} to improve readability and interactivity?: " answer
        CheckYesOrNo "$answer" && IS_TYPING=true || IS_TYPING=false
    }
    
    CheckYesOrNo() {
        local input
        [[ -n $1 ]] && input=$1 || input=$2

        if [[ "$input" =~ ^[:space:]*[Yy].* ]]; then
            return 0
        elif [[ "$input" =~ ^[:space:]*[Nn].* ]]; then
            return 1
        else
            local answer; read -rp "Unknown Input, please type Y, y, N or n. Try again: " answer
            CheckYesOrNo "$answer" && return 0 || return 1
        fi
    }
    
    Log(){
        echo "$1" >> "$Log_Path"
    }
    
    CheckLog(){
        grep -Fq "$1" "$Log_Path"
    }
    
    Trim(){
        echo "$1" | sed -E 's/^\s+//;s/\s+$//'
    }
    
    Typing(){
        local text if_new_line="true" is_ansi="false"
        [[ $1 == "-n" ]] && { if_new_line=false; shift 1; }
        [[ $# -eq 0 ]] && { echo "${R}BUG${I}: No text provided." >&2; exit 1; }
    
        text="${*}"

        if [[ $IS_TYPING == "false" ]]; then
            echo -e -n "$text"
        elif [[ $IS_TYPING == "true" ]]; then
            for (( i=0; i<${#text}; i++ )); do
                if [[ $is_ansi == "false" && "${text:$i:1}" = $'\e' ]]; then
                    is_ansi=true
                elif [[ $is_ansi == "true" && "${text:$i:1}" = "m" ]]; then
                    is_ansi=false
                fi

                echo -e -n "${text:$i:1}"
                [[ $is_ansi == "false" ]] && sleep 0.034
            done
        else
            echo -e "${R}BUG${I}: Environment variable \$IS_TYPING not set or invalid."
        fi
        
        [[ $if_new_line == "true" ]] && echo || return 0
    }

    LocateSshdConfig(){
        echo "/etc/ssh/sshd_config"
    }

    LocateSshdConfigBak(){
        echo "$(LocateSshConfig).bak"
    }
}

InitializeLocal(){
    Tmp_Dir="/tmp/Server_Initialization"
    declare -g Local_Work_Dir Remote_Work_Dir
    declare -g Key_Dir Restore_Dir 
    declare -g Log_File
    declare -g Host User Port Ssh_Socket

    InitializeEnvironment(){
        GetServerInfo "$@"

        Local_Work_Dir="$Tmp_Dir/$Host"
        Remote_Work_Dir="$Tmp_Dir"
        Key_Dir="$Local_Work_Dir/Key"
        Restore_Dir="$Local_Work_Dir/Restoration"

        Log_File="$Restore_Dir/log"
        Ssh_Socket="/tmp/$User@$Host:$Port.sock"
    
        mkdir -p "$Key_Dir"
        mkdir -p "$Restore_Dir"
    }

    GetServerInfo(){
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--host)
                    Host="$2"; shift 2 ;;
                -u|--user)
                    User="$2"; shift 2 ;;
                -p|--port)
                    Port="$2"; shift 2 ;;
                *)
                    echo "Unknown argument: $1"; exit 1 ;;
            esac
        done

        [[ $Host ]] || { Typing -n "Now, what's the server's ${G}IP or domain${I}?: "; read -r Host; }
        [[ $User ]] || { Typing -n "What's the admin user's ${G}name${I}? [Default to \"${G}root${I}\"]: "; read -r User; }
        [[ $Port ]] || { Typing -n "What's the SSH ${G}port${I}? [Default to 22]: "; read -r Port; }
        
        Host=$(Trim "$Host")
        User=$(Trim "${User:-root}")
        Port=$(Trim "${Port:-22}")
        echo "Host: $Host"
        echo "Admin user: $User"
        echo "Port: $Port"

        [[ $Host && $User && $Port ]] || { echo "No info provided. Aborting..."; exit 1; }
    }

    SetUp(){
        ### Create master socket
            rm -rf "${SSH_Socket:?}" # In case last setup was disrupted after creating master socket but before copying any setup files 
            Typing "Let's first create a ${Y}master SSH connection${I}. It's essentially one persisting and reusable connection, saving you from retyping passwords repeatedly."
            Typing "It will prompt for password. On Linux, password won't show up while typing for the sake of security, so don't be surprised."
            CreateMasterSshConnection
            echo -e "Master SSH connection ${G}created${I} at $Ssh_Socket"
            echo

        ### Copy files
            Typing "${Y}Logging in${I} as admin user..."
            SshRunCommand "mkdir -p $Remote_Work_Dir"
            SftpToRemote "$Remote_Work_Dir" "$Script_Path"
            local remote_script="$Remote_Work_Dir/$Script_Name"
            echo -e "Script copied."
            echo
    
        ### Set up
            SshRunCommand "IS_TYPING=$IS_TYPING bash $remote_script --set_up_1"
            echo
    
        ### Retrieve keys back
            SftpFromRemote "$Key_Dir" "$Remote_Work_Dir/*.key"
            Log "$Private_Keys_Fetched"
            compgen -G "$Key_Dir/*.key" >/dev/null || { Typing "${R}ERROR:${I} No private key retrieved from remote."; exit 1; }
            Typing "${G}Private keys fetched${I} and stored under $Key_Dir. ${G}Keep them safe!${I}"
            echo
    
            local ssh_config_dir="$HOME/.ssh/config"
            mkdir -p "$ssh_config_dir"
            local base timestamp; timestamp=$(date +"%Y-%m-%d-%H:%M")
            Log "$Private_Keys_Added $timestamp"
            local k; for k in "$Key_Dir"/*.key; do
                base=$(basename "$k" .key)
                cp "$k" "$ssh_config_dir/${base}.${timestamp}.key"
            done
            chmod 600 "$ssh_config_dir/"*.key
            Typing "Private keys copied to $ssh_config_dir. It's a folder ssh checks automatically when connecting to a remote server."
            echo
    
        ### 
            SshRunCommand "IS_TYPING=$IS_TYPING bash $remote_script --set_up_2"
            Typing "Everything is set up."
            echo
    
        ### Retrieve files for restoration back
            local -a files; for file in user.log backup.nft root_authorized_keys log; do
                files+=("$Remote_Work_Dir/$file")
            done
            # File backup.nft and root_authorized_keys may not exists, thus use "|| true" to catch errors.
            SftpFromServer "$Restore_Dir" "${files[@]}"
            Log "$Restore_Files_Fetched"
            Typing "Files needed for restoration copied under $Restore_Dir."
            echo
    
        ### Apply and Clean up
            SshRunCommand "rm -rf $Remote_Work_Dir"
            Typing "Cleaned up setup files for server."
            echo
    
            RestartSsh
            echo
    
            rm "$Ssh_Socket"
            Typing "Master SSH connection socket removed. No one can exploit it now."
            echo
        
        ### :)
            Typing "${G}You're all set!${I}"
            Typing "${G}Enjoy!${I}"
    }

    Restore(){
        Typing "You've run this script for $Host before. ${Y}Something went wrong?${I} Don't worry, ${Y}let's restore everything!${I}"
    
        TryConnectToRestorationServer
        echo
    
        if SshRunCommand "[[ -d $Remote_Work_Dir ]]"; then
            echo "Detected neccessary files still left on server."
        else
            local files_to_upload=("$Common_Script" "$Restore_Script" "$Restore_Dir/*")
            SftpToserver "$This_Dir" "${files_to_upload[@]}"
            echo "Neccessary files copied."
        fi
        echo
    
        SshRunCommand "IS_TYPING=$IS_TYPING bash $Remote_Work_Dir/server_restore.sh"
        echo "Everything restored."
        echo
    
        SshRunCommand "rm -rf ${Remote_Work_Dir:?}"
        echo "Set-up files removed from server."
        echo
    
        SshRunCommand "systemctl restart ssh"
        echo "Ssh service restarted."
        echo
        
        rm "$Ssh_Socket"
        echo "Master Ssh connection socket removed."
        echo
    
        rm -rf "${Local_Work_Dir:?}"
        echo "Related files removed from local machine."
        echo
    
        echo -e "${G}You're all set${I}."
    }

    InitializeLocalSetUp(){
        CreateMasterSshConnection(){
            local key_option; [[ $1 ]] && key_option="-i $1"
            eval "ssh -f -M -o ControlPath=$Ssh_Socket -o ControlPersist=yes $key_option -p $Port $User@$Host sleep 1"
        }
    
        RestartSsh(){
            Typing "${Y}About to reload SSH service. All changes will take effect.${I}"
            Typing "${R}Make sure having private keys locally if password authentication is disabled.${I}"
            
            local response
            Typing -n "Restart service(Y/n): "; read -r response
            if CheckYesOrNo "$response" Y; then
                Typing "${G}Restarting${I} SSH service..."
                SshRunCommand "systemctl reload ssh"
                Typing "SSH service restarted"
            else
                Typing "${G}Skipped${I} reloading SSH service."
                Typing "Please reload ${G}manually${I} when ready for changes to apply."
            fi
        }
    
        SshRunCommand(){
            ssh -S "$Ssh_Socket" -p "$Port" "$User@$Host" "$1"
        }
    
        SftpToServer(){
            local dest="$1" files=("${@:2}")
            local command
        
            command+="cd $dest"$'\n'
            for file in "${files[@]}"; do
                command+="put $file"$'\n'
            done
            command+="bye"
        
            sftp -o "ControlPath=$Ssh_Socket" -o "Port=$Port" "$User@$(NormalizeHOst)" <<< "$command"
        }
    
        SftpFromServer(){
            local dest="$1" files=("${@:2}")
            local command
        
            command+="lcd $dest"$'\n'
            for file in "${files[@]}"; do
                command+="get $file"$'\n'
            done
            command+="bye"
            
            sftp -o "ControlPath=$Ssh_Socket" -o "Port=$Port" "$User@$(NormalizeHost)" <<< "$command"
        }
    
        NormalizeHost(){
            # SFTP mistakes colon as file name separator due to historical convention "user@host:file"
            [[ "$Host" == *:* ]] && echo "[$Host]" || echo "$Host"
        }
    }

    InitializeLocalRestore(){
        TryConnectToRestorationServer(){
            if [[ -S "$Ssh_Socket" ]]; then
                Typing "Found the master connection socket."
                return 0
            fi
        
            if CreateMasterSshConnection; then
                Typing "Successfully created new master connection."
                return 0
            fi
        
            local root_key_path="$Key_Dir/*$User.key"
            if CreateMasterSshConnection "$root_key_path"; then
                Typing "Found root user's private key. Successfully created new master connection."
                return 0 
            fi 
            
            Typing "Logging in as root user disabled. Let's log in as someone in sudo group."
            LogInSudoAndEnableRootLogIn
        
            CreateMasterSshConnection
        }

        LogInSudoAndEnableRootLogIn(){
            local username; Typing -n "Sudo group user's name: "; read -r username
            username=$(Trim "$username")
        
            local key_path="$Key_Dir/$username.key"
            local user_ssh_socket="/tmp/$username@$Server_IP:$Port.sock"
        
            if ssh -f -M -S "$user_ssh_socket" -o ControlPersist=yes -p "$Port" "$username"@"$Server_IP" sleep 1; then
                Typing "Successfully logged in as $username."
            elif ssh -f -M -S "$user_ssh_socket" -o ControlPersist=yes -i "$key_path" -p "$Port" "$username"@"$Server_IP" sleep 1; then
                Typing "Successfully logged in as $username using private key."
            else 
                Typing "${R}ERROR${I}: Failed to log in as user $username. Please retry. Re-deploy at the provider as the last restort."
                exit 1
            fi
        
            ssh -S "$user_ssh_socket" -p "$Port" "$username"@"$Server_IP" "sudo sed -i -e 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
            Typing "Enabled logging in as root and password authentication."
        
            rm -rf "${user_ssh_socket:?}"
        }
    }
}

LocalMain() {
    CheckIfTyping
    echo

    InitializeEnvironment "$@"
    echo

    if [[ -f "$Log_File" ]]; then
        InitializeLocalRestore
        LogInAndRestore
    else
        InitializeLocalSetUp
        SetUp
    fi
}

InitializeRemoteSetUp(){
    Script_Dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    Log_Path="$Script_Dir/log"
    User_Record="$Script_Dir/new_users"
    
    Os=""
    Update_Cmd=""
    Install_Cmd=""

    Sshd_Config="$(LocateSshConfig)"
    New_Ssh_Port=""
    Initial_Ssh_Port=$(grep -E "^[[:space:]]*#?[[:space:]]*Port" "$Sshd_Config" | awk '{print $2}')
    
    New_Users=()
    
    Hostname=""

    InitializeSystemInfo(){
        Typing "Some features of this script ${Y}aren't applicable to all Linux distributions${I}. Different distro ships with different packages and different package managing system. The script can't cover them all. Don't worry, those aren't critical. You can always set them up manually."
    
        local os_file="/etc/os-release"
        if [[ -f /etc/Os-release ]]; then
            source "$os_file"
            Os=$ID
        else 
            Typing "${R}ERROR${I}: Can't find file $os_file. Maybe a legacy distro."
            Os="Unknown"
            return 1
        fi
    
        case "$Os" in
            almalinux|centos|rocky)
                Update_Cmd="dnf update -y"
                Install_Cmd="dnf install -y"
                ;;
            debian|ubuntu)
                Update_Cmd="export DEBIAN_FRONTEND=noninteractive && apt-get update -y && apt-get dist-upgrade -o Dpkg::Options::=\"--force-confold\" -o Dpkg::Options::=\"--force-confdef\" && apt-get autoremove -y"
                Install_Cmd="apt-get install -y"
                ;;
            fedora)
                Update_Cmd="dnf upgrade --refresh -y"
                Install_Cmd="dnf install -y"
                ;;
            *)
                Typing "${Y}Unfortunately${I} your system $Os is not supported. "
                Typing "Supported distro: debian, ubuntu, almalinux, centos, rocky and fedora."
                Os="Unsupported"
                return 1
                ;;
        esac
    
        Typing "Your system $Os is ${G}supported${I}."
        echo -e "Update command: $Update_Cmd"
        echo -e "Installation command: $Install_Cmd"
    }

    ChangeHostname(){
        Typing "You can ${Y}name the system${I}. It may help with identification. "
    
        # Query current hostname
        local original
        if hostnamectl status --static > /dev/null ; then
            original=$(hostnamectl status --static)
            Hostname="$original"
            Typing "Your current hostname is $original."
        else
            Typing -e "${R}ERROR${I}: Cannot identify current hostname."
            Typing "No worries. You can always change the hostname manually later."
            return 0
        fi
    
        # Retrieve and check new hostname
        local new
        Typing "Have a better name in mind? "
        Typing -n "Type the new hostname (blankspace not allowed), return if no change: "; read -r new
        while  true; do
            new="$(Trim "$new")"
            [[ -z "$new" ]] && { Typing "${G}Skipped${I} changing hostname."; return 0; }
            if echo "$new" | grep -q " "; then
                echo -e -n "${R}ERROR${I}: Blankspace is not allowed. Try again: "; read -r new
            else
                break
            fi
        done
        
        Hostname="$new"
        hostnamectl set-hostname "$new"
        Log "$Hostname_Modified $original"
        Typing "${G}Hostname changed${I} to $(hostnamectl status --static)."
    }

    EditHostsFile(){
        local hosts_file="/etc/hosts"
        Typing "We also need to reflect the change in file /etc/hosts. It's a historic file mapping hostname and local IP. It's still referenced by some tools."
        if ! CheckOsSupport; then
            Typing "However, we don't know the $hosts_file file structure of your distro."
            Typing "You may need to modify manually afterwards."
            return 0
        fi

        cp "$hosts_file" "$hosts_file.bak"
        Typing "Backup file created: $hosts_file.bak"
        Log "$Hosts_File_Modified"

        case "$Os" in
            debian|ubuntu)
                echo "127.0.1.1 $new" > /etc/hosts
                ;;
            almalinux|centos|rocky|fedora)
                echo "127.0.0.1 $new $new.localdomain $new.localdomain4" > /etc/hosts
                echo "::1 $new $new.localdomain $new.localdomain6" > /etc/hosts
                ;;
        esac
        Typing "${G}Successfully modified $hosts_file.${I}"

        if grep -q "/etc/cloud/" /etc/hosts; then
            Typing "${Y}WARNING:${I} Your server provider uses Cloud-Init, which means that after reboot, your server will follow cloud templates and forget all about modified $hosts_file."
            Typing "To make things persist, you need to manually disable Cloud-Init or change the template."
        fi
    }

    AddNewUser(){
        Typing "${Y}Operating as admin user is discrouraged${I}. They can easily cause irreversible harms accidentally, e.g., permanent deletion of important files."
        Typing "Let's create some non-admin users! They can still gain admin priviledge if they are in the \"sudo\" group, which means \"superuser do.\""
        
        local new_user more="true" 
        while $more; do
            Typing -n "New user name (blank space not allowed, use \"_\" instead): "; read -r new_user
            new_user="$(Trim "$new_user")"
            if ! useradd -m "$new_user"; then
                Typing "${R}ERROR${I}: Failed to add user $new_user."
                Typing "Don't worry. Let's try again."
                more=true
                continue
            else 
                LogUser "$new_user"
                New_Users+=("$new_user")
                echo -e "${G}Added user $new_user${I}"
            fi

            chown -R "$new_user":"$new_user" "/home/$new_user" # In case where new user's home directory belongs the admin user

            local password_matched="false"
            while [[ $password_matched == false ]]; do
                passwd "$new_user" && password_matched=true || Typing "Retrying setting password..."
            done

            local if_sudo; Typing "Add $new_user to the ${G}sudo group${I}? (Y/n):  "; read -r if_sudo
            if CheckYesOrNo "$if_sudo" Y; then
                usermod -aG sudo "$new_user"
                echo -e "${G}Added${I} $new_user to sudo group."
            else 
                echo -e "${G}Skipped${I} adding $new_user to sudo group."
            fi

            Typing -n "Do you wish to add ${G}more${I} users? (y/N): " more
            CheckYesOrNo "$more" N && more=true || more=false
        done
    }

    EnableSudoGroup(){
        local sudoers_config="/etc/sudoers"
        Typing "${Y}Some distros need to manually enable super-user privilege even for sudo group${I}. Let's have a check..."
        
        if grep -q '^ *%sudo ALL=(ALL:ALL) ALL' "$sudoers_config"; then
            Typing "Your system ${G}already granted${I} sudo group super user privilege. Let's simply proceed to the next operation."
            return 0
        fi
    
        Typing " ${Y}Manual enabling required.${I}."
        # It's risky to directly modify the sudoers file. Visudo is the way to go.
        # .bak file is for restoration process
        local tmp_file="$sudoers_config.tmp"
        local bak_file="$sudoers_config.bak"
        cp "$sudoers_config" "$bak_file"
        cp "$sudoers_config" "$tmp_file"
        sed -i 's/^# *\(%sudo ALL=(ALL:ALL) ALL\)/\1/' "$tmp_file"
        if visudo -csf "$tmp_file"; then
            mv "$tmp_file" "$sudoers_config"
            Typing "${G}Successfully granted${I} sudo group super-user privilege."
            Log "$Sudoers_Modified"
        else 
            rm "$tmp_file" "$bak_file"
            Typing "${R}ERROR${I}: Something went wrong. You need manually grant later."
        fi
    }

    GenerateSshKey(){
        Typing "It's much safer to ${Y}use keys to log in${I} instead of password."
        Typing "Keys are essentially files containing long random characters, so attackers can never force their way in."
        Typing "Key can be wrapped in password again, offering double layers of protection."
        Typing "${Y}Let's generate some SSH keys!${I}"
        
        local comment all_users=("${New_Users[@]}" "$(whoami)")
        local u; for u in "${all_users[@]}"; do
            Typing "Do you wish to ${G}comment${I} the key for user ${G}$u${I}? Comment helps with ${G} identification${I}. A common practice is using email. Return if no comment."
            Typing -n "Your comment: "; read -r comment
            comment=$(Trim "$comment")

            ssh-keygen -t ed25519 -o -a 256 -C "$comment" -f "$Script_Dir/${Hostname}_${u}.key"
    
            echo -e "${G}Keys generated for user $u.${I}"
        done
        Typing "${G}All keys generated.${I}"
    }

    AddPublicKey(){
        Typing "Each generation outputs two keys: ${Y}private and public${I}. Private key is the \"passport\", while public key is adminstrator. For one private key to work, the corresponding public key must be recorded under the user's authorized_keys file."
        Typing "(One user can actually have multiple public-private key pairs)"
    
        # Back up orginal root user's key, for restoration
        local root_keys="$HOME/.ssh/authorized_keys"
        [[ -f "$root_keys" ]] && cp "$root_keys" "$root_keys.bak"

        local home all_users=("${New_Users[@]}" "$(whoami)")
        local u; for user in "${all_users[@]}"; do
            home=$(eval "echo ~$user")
            mkdir -p "$home/.ssh"
            cat "$Script_Dir/${Hostname}_${user}.key.pub" >> "$home/.ssh/authorized_keys"
            chown "$user:$user" "$home/.ssh/authorized_keys"
            chmod 600 "$home/.ssh/authorized_keys"
            echo -e "Added key for user $user"
        done
        Log "$Public_Key_Added"
        Typing "${G}Successfully added all public keys.${I}"
    }

    CheckUserShell(){
        Typing "To enhance user experience, it's good to ${G}check the users' shell${I}."
        Typing "Shells are essentially interfaces allowing you to interact with the kernel with command lines, like a shell wrapper, therefore the name."
        Typing "There are many shells: dash, bash, zsh, ksh, fish... Some are optimized for desktop environment, and some are for special scenariOs, like git-shell."
        Typing "Shells are not always compatible. Thus, one shell's script may work on another."
        Typing "${G}Bash${I} should be the safest choice for most servers. It's default on many distros and the most common one. You can also try zsh if you want something fancier."

        Typing "Here's a list of shells installed on your system:"
        cat /etc/shells || { Typing "${Y}ERROR${I}: Command \`cat /etc/shells\` can't list installed shells. You may need to manually check later."; return 0; }

        local answer
        for user in "${New_Users[@]}"; do
            echo -e "User $user's shell is $(getent passwd "$user" | cut -d: -f7)"
            if ! ( getent passwd "$user" | cut -d: -f7 | grep -q "/bin/bash" ) && ( grep -q "/bin/bash" /etc/shells ); then
                Typing -n "Change to bash? (Y/n): "; read -r answer
                if CheckYesOrNo "$answer" Y; then
                    chsh -s /bin/bash "$user"
                    echo -e "${G}Successfully changed${I} user $user's shell to bash."
                else 
                    echo -e "${G}Skipped${I} changing user $user's shell."
                fi
            fi
        done
        Typing "Checked all users' shell."
    }

    CheckTimeSynchronization(){
        Typing "It's important to have correct ${Y}timekeeping${I} so network and logging can work correctly."
        Typing "${Y}Let's have a fast check${I}..."

        if timedatectl show | grep -qE 'NTPSynchronized|TimeUSec' || ps aux | grep -E 'chronyd|ntpd|openntpd'; then
            Typing "${G}The system has correct timekeeping.${I}"
        else
            Typing "${R}ERROR:${I} No NTP process found. You may need to troubleshoot manually later."
        fi
    }

    CreateSshConfigBackup(){
        Typing "We are about to ${Y}edit ssh configurations${I}. Let's first create a backup."
        cp -i "$Sshd_Config" "${Sshd_Config}.bak"
        echo -e "${G}Backup created${I} under $Sshd_Config.bak"
        Log "$Ssh_Config_Backed_Up"
    }
    
    EnablePublicKeyAuthentication(){
        Typing "For key auth to work, it needs to be enabled first. Most distros should have it enabled by default."
        if grep -q "PubkeyAuthentication yes" "$Sshd_Config"; then
            Typing "Public key auth already enabled."
            return 0
        else
            Typing "Public key auth not enabled."
            sed -i "s/^ *PubkeyAuthentication.*/PubkeyAuthentication yes/" "$Sshd_Config"
            Typing "${G}Enabled${I} public key authentication: $(grep "PubkeyAuthentication" "$Sshd_Config")"
        fi
    }
    
    ChangeSshPortAndAllow(){
        Typing "22 is the convention SSH port. It therefore expects the most attacks. It's advised to ${Y}change${I} to port within ${Y}number 49152 and 65535${I}."
        echo "(Technically you can use any port between 0 and 65535, but ports before 1024 are reserved for well-known use conventions, e.g., 53 for DNS queries and 443 for HTTPS traffic, and numbers between 1024 and 49152 are registered ports for not so well-known or other strict use cases. To avoid conflict in the future, it's best to just leave them alone.)"
        
        if ! CheckOsSupport; then
            echo -e "Unfortunately, you distros is not ${Y}supported${I}. It may have default firewall applications. Changing SSH port may not get reflected automatically, therefore blocking connections to the new port."
            Typing "Refer to the distros diagnostic tutorial to change the port."
            return 0 
        fi

        Typing "(Changing port won't interrupt current connection until SSH service is restarted)"
        local new_port; while true; do
            Typing -n "Type the new port, return if no change: "; read -r new_port
            new_port=$(Trim "$new_port")
            if [[ -z $new_port ]]; then
                Typing "Skipped changing SSH port."
                return 0
            elif [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -gt 0 ] && [ "$new_port" -le 65535 ]; then
                sed -i "s/^#\?Port.*/Port $new_port/" "$Sshd_Config"
                New_Ssh_Port=$new_port
                Typing "SSH port ${G}changed${I}: $(grep "^Port" "$Sshd_Config")"
                break
            else 
                Typing "${R}ERROR${I}: Invalid input. Please choOse a number between 0 and 65535. Let's try again."
            fi
        done
    
        if systemctl status firewalld > /dev/null 2>&1; then
            # firewall-cmd --permanent --remove-port="$Initial_Ssh_Port/tcp" # Commented out in case user has changed ssh port but doesn't restart ssh service 
            firewall-cmd --permanent --zone=public --add-port="$new_port/tcp"
            firewall-cmd --reload
        fi
        if sestatus > /dev/null 2>&1; then
            # semanage port -d -t ssh_port_t -p tcp "$Initial_Ssh_Port"
            semanage port -m -t ssh_port_t -p tcp "$new_port"
        fi
        if ufw --version > /dev/null 2>&1; then
            # ufw deny "$Initial_Ssh_Port"
            ufw allow "$new_port/tcp"
        fi
        Typing "Firewall rules updated (if there are any) to allow incoming traffic to $new_port."
        Typing "${Y}WARNING: Some server providers have an external layer of firewall${I}. You need to update it manually."
    }
    
    DisablePasswordLogin(){
        Typing "It's suggested to ${Y}disable password log-in${I} completely to minimize the risk of brute-force or dictionary attack."
        Typing "${R}WARNING${I}: Ensure that you have the private key locally before disabling!"
    
        local response
        Typing -n "Disable it? (Y/n): "; read -r response
        if CheckYesOrNo "$response" Y; then
            sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" "$Sshd_Config"
            Typing "Password auth ${G}disabled${I}: $(grep "^PasswordAuthentication" "$Sshd_Config")"
        else 
            Typing "Skipped disabling password authentication."
        fi
    }
    
    DisableRootLogin(){
        Typing "It's suggested to ${Y}disable root log-in${I}, especially if you haven't disabled password authentication. You can still switch to root user from normal user using command \`su\`."
        Typing "(Technically you can keep root log-in if password log-in is disabled, but since it's advised to operate as normal users...)"
    
        local response
        Typing -n "Disable it? (Y/n): "; read -r  response
        if CheckYesOrNo "$response" Y; then
            sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$Sshd_Config"
            Typing "${G}Disabled${I} root login: $(grep "^PermitRootLogin" "$Sshd_Config")"
        else 
            Typing "${G}Skipped${I} disabling root login."
        fi
    }
    
    ChangeRootPassword(){
        [[ $(whoami) != "root" ]] && return 0
        Typing "One may often find the need to switch to root user. You may wish to ${Y}change the root password${I} to something familiar."
        Typing "${Y}WARNING${I}: This is only recommended if password or root log-in is disabled, else it's much safer to use randomly generated password."
    
        while true; do
            local response; Typing -n "Change root password? (y/N): "; read -r  response
            if CheckYesOrNo "$response" N; then
                if ! passwd; then
                    Typing "${R}ERROR${I}: Something went wrong. Let's try again."
                else
                    Log "$Root_Password_Modified"
                    Typing "${G}Successfully${I} changed the root user's password."
                fi
            else
                Typing "${G}Skipped${I} changing root user's password."
                break
            fi
        done
        
    }
    
    UpdatePackages(){
        Typing "The shipped system from provider may not always be up-to-date. It's generally recommended to ${Y}update all pre-installed packages${I} in case there are security patches."
        Typing "${Y}This may take a while.${I}"
        
        if ! CheckOsSupport; then
            Typing "Unfortunately, we don't know your distro's package manager. You need to perform update manually later."
            return 0
        fi
    
        local answer; echo -n "Update? (y/N): "; read -r answer
        if CheckYesOrNo "$answer" N; then
            Log "$Package_Updating"
            if eval "$Update_Cmd"; then
                Log "$Package_Updated"
                echo -e "${G}All packages successfully updated.${I}"
            else
                echo "${R}Something went wrong${I}. You may need to troubleshoot manually later."
            fi
        else 
            echo -e "${G}Skipped${I} updating packages."
        fi
    }
    
    InstallFirewall(){
        Typing "Internet is ${Y}hostile${I} towards those with public IP. Attacks happen constantly, e.g., the most common brute-force attack or DDOs attack." 
        Typing "Linux uses ${Y}Netfilter${I} to manage network operations. Tools like ${Y}iptables and nftables${I} builds on it, offering interfaces for management."
        Typing "You can use nftables or iptables directly for ${Y}advanced routing rules${I}. But most servers, there are much more user-friendly tools built on them."
    
        case "$Os" in
            debian|ubuntu)
                Typing "For Debian-based distros, ${G}ufw${I} is a solid choice."
                InstallUfw
                ;;
            almalinux|centos|rocky|fedora)
                Typing "RHEL-based distros ship with ${G}Firewalld${I} with predefined rules by default. No more action is needed."
                ;;
            *)
                Typing "Your distro $Os is ${Y}not supported${I}. It may or may not have a firewall pre-installed. Please refer to the distro's official doc."
                ;;
        esac
    }
    
    InstallFail2Ban(){
        Typing "${Y}Fail2Ban${I} is another tool to protect servers. Unlike firewall inspecting raw networks packets directly, Fail2Ban scans the system log and bans visitors with too many failures."
        Typing "It has ${Y}rich and powerful${I} features: It can do random increment, send mails, report malicious IP..."
        Typing "Many features require sepecial configuration, but it still ${Y}works out of box${I} with default protection over many protocols, including SSH."
        Typing "However, it's ${Y}not strictly neccessary${I} to install Fail2Ban, especially if password auth is already disabled."
    
        if command -v fail2ban >/dev/null 2>&1; then
            echo -e "${G}Fail2Ban already installed. Skipping...${I}"
            return 0
        fi
    
        local response; Typing -n "Install Fail2Ban? (Y/n): "; read -r response
        if ! CheckYesOrNo "$response" Y; then
            Typing "${G}Skipped${I} installing Fail2Ban."
            return 0
        fi
        
        case "$Os" in
            debian|ubuntu)
                eval "$Install_Cmd fail2ban"
                Typing "Fail2Ban ${G}successfully installed${I}."
                ;;
            almalinux|centos|rocky|fedora)
                Typing "For RHEL-based distributions, Fail2Ban is inside Extra Packages for Enterprise Linux (EPEL) repository. (The default Red Hat Enterprise Linux (RHEL) repository only offers core packages.)"
                Typing "Let's first enable that repository."
                eval "$Install_Cmd epel-release"
                Typing "EPEL repository ${G}successfully enabled${I}."
                eval "$Install_Cmd fail2ban"
                Typing "Fail2Ban ${G}successfully installed${I}."
                ;;
            *)
                Typing "Your system $Os is ${Y}currenly not supported${I}. You may need to install manually later."
                return 0 
        esac
        Log "$Fail2ban_Installed"

        local default_config="/etc/fail2ban/fail2ban.conf"
        local local_cnfig="/etc/fail2ban/fail2ban.local"
        cp "$default_config" "$local_cnfig"
        local max_retry; max_retry=$(grep -m1 "^maxretry" $local_cnfig | awk -F= '{print $2}' | tr -d ' ')
        local ban_time; ban_time=$(grep -m1 "^bantime" $local_cnfig | awk -F= '{print $2}' | tr -d ' ')
        local find_time; find_time=$(grep -m1 "^findtime" $local_cnfig | awk -F= '{print $2}' | tr -d ' ')
        Typing "Your current configuration bans failed attempts for $ban_time after $max_retry times within $find_time."
    
        systemctl enable fail2ban
        systemctl start fail2ban
        Typing "Fail2Ban started and is now protecting your server."
    }
    
    InstallUfw(){
        Typing "ufw stands for ${Y}Uncomplicated Firewall${I}. It's a simple yet user-friendly firewall tool built on iptables."
        
        if command -v ufw >/dev/null 2>&1; then
            echo -e "${G}ufw already installed. Skipping...${I}"
            return 0
        fi
    
        Typing "Install ufw? Don't worry if you don't. A default nftable rules will apply to protect your server."
        local response; Typing -n "Your answer (Y/n): "; read -r response
        if ! CheckYesOrNo "$response" Y; then
            Typing "${G}Skipped${I} installing ufw."
            SetUpDefaultNftablesRules
        else
            Typing "Installing ufw..."
            eval "$Install_Cmd ufw"
            Typing "ufw ${G}successfully installed${I}."
            Log "$Ufw_Installed"
    
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow "$Initial_Ssh_Port/tcp"
            [[ -n $New_Ssh_Port ]] && ufw allow "$New_Ssh_Port/tcp"
            Typing "Denied all inbound connection except towards SSH port. Allowed any outbound connection."
        
            ufw enable
            Typing "ufw enabled and will start automatically at boot."
        fi
    }
    
    SetUpDefaultNftablesRules(){
        if ! command -v nft > /dev/null 2>&1; then
            Typing "Nftables not installed. Installing..."
            eval "$Install_Cmd nftables"
            Log "$Nftables_Installed"
        fi

        local bak="$Script_Dir/backup.nft"
        nft list ruleset > "$bak"
        Typing "Original nftables rules backed up."
    
        nft -f <"$(TemplateNftables)"
        Log "$Nftables_Rule_Modified"
        [[ -n $New_Ssh_Port ]] && nft add rule inet filter input tcp dport "$New_Ssh_Port" accept
        Typing "Nftables rules added."

        nft list ruleset > /etc/nftables.conf
        sudo systemctl enable nftables
        sudo systemctl start nftables
        Typing "Nftables enabled as system service. The rule will persist after reboot."

        nft add rule inet filter input tcp dport "$Initial_Ssh_Port" accept # In case user has changed ssh port but doesn't restart ssh service 
    }
    
    LogUser(){
        echo "$1" >> "$User_Record"
    }

    ParseUserFromRecord(){
        readarray -r New_Users < "$User_Record"
    }

    CheckOsSupport(){
        echo "$Os" | grep -iqE "unsupported|unknown" && return 1 || return 0
    }
}

RemoteSetUp1(){
    CheckIfSudo

    InitializeSystemInfo
    echo

    ChangeHostname
    echo

    EditHostsFile
    echo

    AddNewUser
    echo

    EnableSudoGroup
    echo

    GenerateSshKey
    echo

    AddPublicKey
    echo
}

RemoteSetUp2(){
    CheckIfSudo

    InitializeSystemInfo >/dev/null 2>&1
    ParseUserFromRecord
    echo

    CheckUserShell
    echo

    CheckTimeSynchronization
    echo

    CreateSshConfigBackup
    echo

    EnablePublicKeyAuthentication
    echo

    ChangeSshPortAndAllow
    echo

    DisablePasswordLogin
    echo

    DisableRootLogin
    echo
    
    ChangeRootPassword
    echo

    UpdatePackages || ( Typing "${R}ERROR${I}: Something went wrong. Failed to update packages. You may need to update manually. Skip firewall related setup..." && exit 0 )
    echo

    InstallFirewall
    echo

    InstallFail2Ban
    echo
}

InitializeRemoteRestore(){
    CheckAnySetup(){
        [[ ! -f "$Log_Path" ]] && { echo "Nothing to restore server-side. Skipping...";  exit 0; } || return 0
    }
    
    InitializeDistroInfo(){
        if [[ -f /etc/Os-release ]]; then
            source /etc/os-release
            Os=$ID
        else 
            Os="Unknown"
            return 0
        fi
    
        case "$Os" in
            almalinux|centos|rocky|fedora)
                Uninstall_Cmd="dnf remove -y"
                ;;
            debian|ubuntu)
                Uninstall_Cmd="apt-get purge -y"
                ;;
            *)
                echo "Unsupported system: $Os"
                return 0
                ;;
        esac
        echo "Uninstall command for your distro $Os is: $Uninstall_Cmd"
    }
    
    FinishUpdate(){
        if CheckLog "$Package_Updating" && ! CheckLog "$Package_Updated" ; then
            Typing "Things seemed to go wrong during packages update. While update is irreversible, partial update can be dangerous. We need to finish it."
            Typing "Finishing packages updating..."
            if eval "$Update_Cmd"; then 
                Log "$Package_Updated"
                Typing "${G}All packages successfully updated.${I}"
                return 0
            else
                Typing "Still failed to update. You need to troubleshoot manually later."
                return 1
            fi
        elif ! CheckLog "$Package_Updating"; then
            Typing "Packages weren't updated. ${G}Skipping${I}..."
            return 0
        elif CheckLog "$Package_Updated"; then
            Typing "${Y}Packages updated${I}. It ${Y}can't be reversed${I}, but it won't do you any harm."
            return 0
        fi
    }  
    
    UninstallFail2Ban(){
        ! CheckLog "$Fail2ban_Installed" && { Typing "Didn't install Fail2Ban. Skipping..."; return 0; }
        eval "$Uninstall_Cmd fail2ban"
        rm -rf /etc/fail2ban
        rm -rf /var/log/fail2ban.log /var/lib/fail2ban
        Typing "${G}Fail2Ban purged.${I}"
    }
    
    UninstallUfw(){
        ! CheckLog "$Ufw_Installed" && { Typing "Didn't install ufw. Skipping..."; return 0; }
        eval "$Uninstall_Cmd ufw"
        Typing "${G}ufw uninstalled.${I}"
    }
    
    RestoreNftables(){
        if CheckLog "$Nftables_Installed"; then
            eval "$Uninstall_Cmd nftables"
            Typing "${G}Nftables uninstalled${I}."
        elif CheckLog "$Nftables_Rule_Modified"; then
            nft flush ruleset
            nft -f "$Script_Dir/backup.nft"
            Typing "${G}Nftable rules recovered${I}."
        else
            Typing "Didn't configure nftable. ${G}Skipping${I}"
        fi
    }
    
    RestoreHostname(){
        ! CheckLog "$Hostname_Modified" && { Typing "Host name wansn't changed. ${G}Sikpping...${I}"; return 0; }
    
        local original
        original=$(grep -F "$Hostname_Modified" "$Log_Path" | awk '{print $NF}')
        hostnamectl set-hostname "$original"
        Typing "Original hostname ${G}restored${I}."
    
        if ! CheckLog "$Hosts_File_Modified"; then
            Typing "File /etc/hosts wasn't changed. ${G}Sikpping...${I}"
        else
            mv /etc/hosts.bak /etc/hosts
            Typing "${G}Restored /etc/hosts.${I}"
        fi
    }
    
    RestoreSudoers(){
        if ! CheckLog "$Sudoers_Modified"; then
            Typing "Sudoers file wasn't modified. ${G}Skipping${I}."
            return 0
        fi
    
        mv /etc/sudoers.bak /etc/sudoers
        Typing "${G}Restored /etc/sudoers.${I}"
    }
    
    RemoveUsers(){
        if [[ ! -f "$USER_LOG_PATH" ]]; then
            Typing "No new user was created. ${G}Skipping${I}"
            return 0
        fi
    
        local user
        local users_array
        mapfile -t users_array < <(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$USER_LOG_PATH" | tr -s ' ' '\n' | grep -v '^$')
        
        for user in "${users_array[@]}"; do
            pkill -u "$user"
            userdel -r "$user"
            echo "Removed user $user."
        done
    
        Typing "${G}All created users removed.${I}"
        Typing "Remaining user:"
        ls /home
        Typing "You may see some users that weren't created by this script, or some that can't be removed because their home directory holds files or folders of others. You may need to remove them manually."
    }
    
    RestoreRootKey(){
        ! CheckLog "$Public_Key_Added" && return 0
        
        local key="$HOME/.ssh/authorized_keys"
        local bak="$key.bak"
        [[ -f "$bak" ]] && mv "$bak" "$key" || rm "$key"
        Typing "${G}Restored $key.${I}"
    }
    
    RecoverSshConfig(){
        if ! CheckLog "$Ssh_Config_Backed_Up"; then
            Typing "Didn't change SSH config. ${G}Skipping${I}"
            return 0
        fi

        local config; config="$(LocateSshdConfig)"
        local bak; bak="$(LocateSshdConfigBak)"

        local current_port; current_port=$(grep -E "^[[:space:]]*#?[[:space:]]*Port" "$config" | awk '{print $2}')
        local initial_port; initial_port=$(grep -E "^[[:space:]]*#?[[:space:]]*Port" "$bak" | awk '{print $2}')
        if systemctl status firewalld > /dev/null 2>&1; then
            firewall-cmd --permanent --remove-port="$current_port/tcp"
            firewall-cmd --permanent --zone=public --add-port="$initial_port/tcp"
            firewall-cmd --reload
        fi
        if sestatus > /dev/null 2>&1; then
            semanage port -m -t ssh_port_t -p tcp "$initial_port"
        fi
        if ufw --version > /dev/null 2>&1; then 
            ufw deny "$current_port"
            ufw allow "$initial_port/tcp"
        fi
        Typing "Firewall rules restored."

        mv "$bak" "$config"
        Typing "SSH config restored. "
    }
    
    InformAboutRootPassword(){
        if CheckLog "$Root_Password_Modified"; then
            Typing "Root user passwrod changed. However, this is irreversible as original password isn't recorded."
        fi
    }
}

RemoteRecoverMain(){
    CheckIfSetupAnything

    CheckIfSudo

    if InitializeInformation; then 
        echo
        FinishUpdate
        echo
        UninstallFail2Ban
        echo
        UninstallUfw
        echo
        UninstallOrRestoreNftables 
        echo
    fi

    RestoreHostname
    echo

    RestoreSudoers
    echo

    RemoveUsers && echo && RestoreRootKey
    echo

    RecoverSshConfig
    echo

    InformAboutRootPassword
}

TemplateNftables(){ cat <<EOF
    #!/usr/sbin/nft -f

    flush ruleset

    table inet raw {
        chain prerouting {
            type filter hook prerouting priority raw;

            # Drops new TCP connections that do not have the SYN flag set
            tcp flags & (fin|syn|rst|ack) != syn ct state new drop

            # Drops NULL packets, meaning TCP packets with no flags set
            tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop

            # Drops TCP packets with all flags set, known as XMAS packets.
            tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) drop
        }
    }


    table inet filter {
        set ipv4_blackroom {
            type ipv4_addr
            flags dynamic, timeout
            timeout 1m
        }

        set ipv6_blackroom {
            type ipv6_addr
            flags dynamic, timeout
            timeout 1m
        }

        chain input {
            type filter hook input priority filter; policy drop;

            # Connection tracking
            ct state {established, related} accept
            ct state invalid drop

            # Local interface
            iifname lo accept
            # Drop external request to local addr to anti-proof
            iifname != lo ip saddr 127.0.0.0/8 drop
            iifname != lo ip6 saddr ::1 drop

            # ICMP/ICMPv6 - essential only
            meta l4proto {icmp, ipv6-icmp} limit rate 20/second accept

            # Blackroom for TCP connections
            meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn limit rate over 50/second add @ipv4_blackroom { ip saddr } drop
            meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn limit rate over 50/second add @ipv6_blackroom { ip6 saddr } drop

            # Blackroom for UDP connections
            meta nfproto ipv4 ip protocol udp limit rate over 1200/second add @ipv4_blackroom { ip saddr } drop
            meta nfproto ipv6 ip6 nexthdr udp limit rate over 1200/second add @ipv6_blackroom { ip6 saddr } drop
        }

        chain forward {
            type filter hook forward priority filter; policy drop;

            # Connection tracking
            ct state {established, related} accept
        }

        chain output {
            type filter hook output priority filter; policy accept;

            # Connection tracking for output
            ct state invalid drop
        }
    }
EOF
}

set -eu
InitializeShared
case "$1" in
    --set_up_1)
        InitializeRemoteSetUp
        RemoteSetUp1
        ;;
    --set_up_2)
        InitializeRemoteSetUp
        RemoteSetUp2
        ;;
    --restore)
        InitializeRemoteRestore
        RemoteRecoverMain
        ;;
    *)
        InitializeLocal
        LocalMain "$@"
        ;;
esac





