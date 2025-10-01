#!/bin/bash
# ==========================
# VPS Toolkit - full version
# ==========================

# --- Ensure running as root ---
if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

# --- Ensure dialog installed ---
if ! command -v dialog &>/dev/null; then
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq dialog >/dev/null 2>&1
fi

# Ustaw logo jako zmienną
if [[ -f /tmp/logo.txt ]]; then
  rm -r /tmp/logo.txt
else
  echo ""
fi

cat <<'EOF' > /tmp/logo.txt
 _______   __    __                __    __                        __
|       \ |  \  |  \              |  \  |  \                      |  \
| $$$$$$$\ \$$ _| $$_     ______  | $$  | $$  ______    _______  _| $$_
| $$__/ $$|  \|   $$ \   /      \ | $$__| $$ /      \  /       \|   $$ \
| $$    $$| $$ \$$$$$$  |  $$$$$$\| $$    $$|  $$$$$$\|  $$$$$$$ \$$$$$$
| $$$$$$$\| $$  | $$ __ | $$    $$| $$$$$$$$| $$  | $$ \$$    \   | $$ __
| $$__/ $$| $$  | $$|  \| $$$$$$$$| $$  | $$| $$__/ $$ _\$$$$$$\  | $$|  \
| $$    $$| $$   \$$  $$ \$$     \| $$  | $$ \$$    $$|       $$   \$$  $$
 \$$$$$$$  \$$    \$$$$   \$$$$$$$ \$$   \$$  \$$$$$$  \$$$$$$$     \$$$$
    
🚀 CLI - vpsTOOLKIT [v1.0]
by Vahistar
EOF

# Wyświetl logo w oknie dialogu
dialog --title "CLI - UFW Manager" --textbox /tmp/logo.txt 20 80

check_installed() { dpkg -l | grep -qw "$1"; }

# ==========================
# --- USER MANAGEMENT ---
# ==========================
add_user() {
    USERNAME=$(dialog --inputbox "Enter new username:" 8 40 --stdout)
    [ -z "$USERNAME" ] && return
    PASS=$(dialog --passwordbox "Enter password for $USERNAME:" 8 40 --stdout)
    [ -z "$PASS" ] && return
    useradd -m "$USERNAME" >/dev/null 2>&1
    echo "$USERNAME:$PASS" | chpasswd >/dev/null 2>&1
    dialog --yesno "Grant sudo to $USERNAME?" 7 50
    [ $? -eq 0 ] && usermod -aG sudo "$USERNAME" >/dev/null 2>&1
    dialog --msgbox "Created user $USERNAME" 7 40
}

manage_user() {
    USER="$1"
    while true; do
        # Get user data
        USER_UID=$(id -u "$USER")
        USER_GID=$(id -g "$USER")
        USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
        USER_SHELL=$(getent passwd "$USER" | cut -d: -f7)
        USER_SUDO=$(groups "$USER" | grep -qw sudo && echo "YES" || echo "NO")
        STATUS=$(passwd -S "$USER" | awk '{print $2}' | sed 's/L/LOCKED/;s/P/ACTIVE/')
        LAST_LOGIN=$(lastlog -u "$USER" | awk 'NR==2 {print $4,$5,$6,$7}')

        # Password information from chage
        PASS_LAST_CHANGE=$(chage -l "$USER" | grep "Last password change" | cut -d: -f2 | xargs)
        PASS_MIN=$(chage -l "$USER" | grep "Minimum" | cut -d: -f2 | xargs)
        PASS_MAX=$(chage -l "$USER" | grep "Maximum" | cut -d: -f2 | xargs)
        PASS_WARN=$(chage -l "$USER" | grep "warning" | cut -d: -f2 | xargs | tr '[:upper:]' '[:lower:]')
        PASS_EXPIRE=$(chage -l "$USER" | grep "Account expires" | cut -d: -f2 | xargs)

        [ -z "$PASS_WARN" ] && PASS_WARN="none"

        INFO="UID: $USER_UID
GID: $USER_GID
Home: $USER_HOME
Shell: $USER_SHELL
Sudo: $USER_SUDO
Status: $STATUS
Last login: $LAST_LOGIN
Password:
  - last change: $PASS_LAST_CHANGE
  - min: $PASS_MIN
  - max: $PASS_MAX
  - warn: $PASS_WARN
  - expires: $PASS_EXPIRE"

        ACTION=$(dialog --clear --stdout --title "User: $USER" \
            --menu "$INFO" 25 80 13 \
            1 "Change password" \
            2 "Force password change on next login" \
            3 "Grant / revoke sudo" \
            4 "Lock / unlock account" \
            5 "Change home directory" \
            6 "Delete account and home directory" \
            7 "Change shell" \
            8 "Set password expiration" \
            9 "Set / change account expiration date" \
            0 "Back")

        case $ACTION in
            1)
                PASS=$(dialog --passwordbox "New password:" 8 40 --stdout)
                if [ -n "$PASS" ]; then
                    echo "$USER:$PASS" | chpasswd
                    dialog --msgbox "Password changed successfully." 7 50
                fi
                ;;
            2)
                chage -d 0 "$USER"
                dialog --msgbox "Password change on next login enforced." 7 60
                ;;
            3)
                if groups "$USER" | grep -qw sudo; then
                    deluser "$USER" sudo
                    dialog --msgbox "Sudo revoked." 7 40
                else
                    usermod -aG sudo "$USER"
                    dialog --msgbox "Sudo granted." 7 40
                fi
                ;;
            4)
                if passwd -S "$USER" | grep -q L; then
                    usermod -U "$USER"
                    dialog --msgbox "Account unlocked." 7 40
                else
                    usermod -L "$USER"
                    dialog --msgbox "Account locked." 7 40
                fi
                ;;
            5)
                NEW_HOME=$(dialog --inputbox "New home directory:" 8 50 --stdout)
                [ -n "$NEW_HOME" ] && usermod -d "$NEW_HOME" -m "$USER" && dialog --msgbox "Home directory changed." 7 50
                ;;
            6)
                dialog --yesno "Delete account and home directory?" 7 50
                if [ $? -eq 0 ]; then
                    pkill -u "$USER"
                    deluser --remove-home "$USER" && dialog --msgbox "Account deleted." 7 50
                    break
                fi
                ;;
            7)
                NEW_SHELL=$(dialog --inputbox "New shell:" 8 50 --stdout)
                [ -n "$NEW_SHELL" ] && [ -x "$NEW_SHELL" ] && usermod -s "$NEW_SHELL" "$USER" && dialog --msgbox "Shell changed." 7 50
                ;;
            8)
                MIN=$(dialog --inputbox "Min days between password changes:" 8 50 --stdout)
                MAX=$(dialog --inputbox "Max days password is valid:" 8 50 --stdout)
                WARN=$(dialog --inputbox "Warning before expiration (days):" 8 50 --stdout)
                [ -n "$MIN" ] && [ -n "$MAX" ] && [ -n "$WARN" ] && chage -m "$MIN" -M "$MAX" -W "$WARN" "$USER" && dialog --msgbox "Password options set." 7 50
                ;;
            9)
                EXP=$(dialog --inputbox "Enter account expiration date (YYYY-MM-DD) or empty to remove:" 8 50 --stdout)
                if [ -n "$EXP" ]; then
                    chage -E "$EXP" "$USER" && dialog --msgbox "Expiration date set to $EXP" 7 50
                else
                    chage -E -1 "$USER" && dialog --msgbox "Account expiration date removed" 7 50
                fi
                ;;
            0) break ;;
        esac
    done
}


user_menu() {
    while true; do
        CHOICE=$(dialog --clear --stdout --title "User Management" \
            --menu "Select option:" 15 60 6 \
            1 "Add new user" \
            2 "Manage existing users" \
            0 "Back")
        case $CHOICE in
            1) add_user ;;
            2) 
                USERS=($(awk -F: '$3>=1000 || $1=="root"{print $1}' /etc/passwd))
                USERS_MENU=()
                for u in "${USERS[@]}"; do USERS_MENU+=("$u" "$u"); done
                USERS_MENU+=("0" "Back")
                USER=$(dialog --stdout --title "Select user" \
                    --menu "Users:" 15 50 10 "${USERS_MENU[@]}")
                [ -z "$USER" ] && continue
                [ "$USER" == "0" ] && continue
                manage_user "$USER"
                ;;
            0) break ;;
        esac
    done
}

# ==========================
# --- FIREWALL (ufw) ---
# ==========================

# Function to parse ports and ranges into individual ports
parse_ports() {
  local input="$1"
  local ports=()

  IFS=',' read -ra parts <<< "$input"
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
      start=${part%-*}
      end=${part#*-}
      if (( start > end )); then
        continue
      fi
      for ((p=start; p<=end; p++)); do
        ports+=("$p")
      done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      ports+=("$part")
    else
      continue
    fi
  done

  # Remove duplicates and sort
  echo "${ports[@]}" | tr ' ' '\n' | sort -n | uniq
}

# Function to display UFW rules in a formatted way
show_ufw_rules() {
  dialog --title "UFW Rules Status" --clear --msgbox "$(ufw status numbered | grep -E "ALLOW" | grep -v "(v6)" || echo 'No allowed ports or firewall is disabled')" 20 80
}

# Function to process ports (add or remove) with protocol support
process_ports() {
  local action=$1
  local ports=$2
  local proto=$3

  local ports_changed=0
  local output=""

  for PORT in $ports; do
    if [[ "$action" == "add" ]]; then
      if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?\s+ALLOW"; then
          output+="Port $PORT (TCP) is already allowed, skipping.\n"
        else
          ufw allow ${PORT}/tcp > /dev/null 2>&1
          output+="Added port $PORT (TCP)\n"
          ports_changed=1
        fi
      fi

      if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/udp)?\s+ALLOW"; then
          output+="Port $PORT (UDP) is already allowed, skipping.\n"
        else
          ufw allow ${PORT}/udp > /dev/null 2>&1
          output+="Added port $PORT (UDP)\n"
          ports_changed=1
        fi
      fi

    else
      if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/tcp)?\s+ALLOW"; then
          ufw delete allow ${PORT}/tcp > /dev/null 2>&1
          output+="Removed port $PORT (TCP)\n"
          ports_changed=1
        else
          output+="Port $PORT (TCP) was not allowed, skipping.\n"
        fi
      fi

      if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
        if ufw status 2>/dev/null | grep -qE "^${PORT}(/udp)?\s+ALLOW"; then
          ufw delete allow ${PORT}/udp > /dev/null 2>&1
          output+="Removed port $PORT (UDP)\n"
          ports_changed=1
        else
          output+="Port $PORT (UDP) was not allowed, skipping.\n"
        fi
      fi
    fi
  done

  if [[ "$ports_changed" -eq 1 ]]; then
    output+="\nReloading UFW...\n"
    ufw reload > /dev/null 2>&1
  else
    output+="\nNo changes were made.\n"
  fi

  echo -e "$output"
}

# UFW control functions
disable_ufw() {
  ufw disable > /dev/null 2>&1
  dialog --msgbox "UFW has been disabled." 7 40
}

enable_ufw() {
  ufw --force enable > /dev/null 2>&1
  # Add port 22 tcp if not present
  if ! ufw status | grep -q "^22/tcp\s\+ALLOW"; then
    ufw allow 22/tcp > /dev/null 2>&1
  fi
  ufw reload > /dev/null 2>&1
  dialog --msgbox "UFW has been enabled.\nPort 22 (SSH) is open." 7 40
}

reset_ufw() {
  ufw --force reset > /dev/null 2>&1
  ufw default deny incoming > /dev/null 2>&1
  ufw default allow outgoing > /dev/null 2>&1
  ufw --force enable > /dev/null 2>&1
  ufw allow 22/tcp > /dev/null 2>&1
  ufw reload > /dev/null 2>&1
  dialog --msgbox "UFW has been reset to factory defaults.\nPort 22 (SSH) is open." 7 40
}

# Function to handle firewall presets
handle_preset() {
  local preset_name=$1
  local ports_tcp=""
  local ports_udp=""

  case "$preset_name" in
    "Web Server")
      ports_tcp="80 443"
      ports_udp=""
      ;;
    "SSH Server")
      ports_tcp="22"
      ports_udp=""
      ;;
    "FTP Server")
      ports_tcp="21"
      ports_udp="20"
      ;;
    "Mail Server")
      ports_tcp="25 465 587 993 995 143 110"
      ports_udp=""
      ;;
    "DNS Server")
      ports_tcp="53"
      ports_udp="53"
      ;;
    "Game Server")
      ports_tcp="25565 27015 7777"
      ports_udp="25565 27015 7777"
      ;;
    *)
      dialog --msgbox "Unknown preset: $preset_name" 7 40
      return
      ;;
  esac

  # Action selection: add, remove, or cancel
  action=$(dialog --menu "What to do with preset $preset_name?" 15 60 3 \
    1 "Add" \
    2 "Remove" \
    3 "Cancel" 3>&1 1>&2 2>&3)

  case $action in
    1)
      # Add TCP and UDP ports
      output=""
      for p in $ports_tcp; do
        if ufw status | grep -q "^${p}/tcp\s\+ALLOW"; then
          output+="Port $p (TCP) is already allowed, skipping.\n"
        else
          ufw allow ${p}/tcp > /dev/null 2>&1
          output+="Added port $p (TCP)\n"
        fi
      done
      for p in $ports_udp; do
        if ufw status | grep -q "^${p}/udp\s\+ALLOW"; then
          output+="Port $p (UDP) is already allowed, skipping.\n"
        else
          ufw allow ${p}/udp > /dev/null 2>&1
          output+="Added port $p (UDP)\n"
        fi
      done
      ufw reload > /dev/null 2>&1
      dialog --title "Preset $preset_name" --msgbox "$output" 15 60
      ;;
    2)
      # Remove TCP and UDP ports
      output=""
      for p in $ports_tcp; do
        if ufw status | grep -q "^${p}/tcp\s\+ALLOW"; then
          ufw delete allow ${p}/tcp > /dev/null 2>&1
          output+="Removed port $p (TCP)\n"
        else
          output+="Port $p (TCP) was not allowed, skipping.\n"
        fi
      done
      for p in $ports_udp; do
        if ufw status | grep -q "^${p}/udp\s\+ALLOW"; then
          ufw delete allow ${p}/udp > /dev/null 2>&1
          output+="Removed port $p (UDP)\n"
        else
          output+="Port $p (UDP) was not allowed, skipping.\n"
        fi
      done
      ufw reload > /dev/null 2>&1
      dialog --title "Preset $preset_name" --msgbox "$output" 15 60
      ;;
    3)
      dialog --msgbox "No changes made to preset $preset_name." 7 40
      ;;
    *)
      dialog --msgbox "Invalid selection." 7 40
      ;;
  esac
}

# Main firewall menu
firewall_menu() {
    while true; do
        CHOICE=$(dialog --clear --stdout --title "Firewall (UFW) Management" \
            --menu "Select option:" 20 70 10 \
            1 "Enable UFW" \
            2 "Disable UFW" \
            3 "Add ports" \
            4 "Remove ports" \
            5 "View rules" \
            6 "Reset UFW" \
            7 "Apply preset" \
            8 "Detailed status" \
            0 "Back")
        case $CHOICE in
            1) enable_ufw ;;
            2) disable_ufw ;;
            3)
                # Protocol selection
                proto_choice=$(dialog --clear \
                    --title "Protocol" \
                    --menu "Select protocol:" 15 50 3 \
                    1 "TCP" \
                    2 "UDP" \
                    3 "TCP/UDP" \
                    3>&1 1>&2 2>&3)

                case $proto_choice in
                    1) proto="tcp" ;;
                    2) proto="udp" ;;
                    3) proto="both" ;;
                    *)
                        dialog --msgbox "No protocol selected. Returning to menu." 7 40
                        continue
                        ;;
                esac

                # Get ports from user
                user_ports_raw=$(dialog --inputbox "Enter ports or ranges (e.g., 80,443,2000-2010):" 10 50 3>&1 1>&2 2>&3)
                if [[ -z "$user_ports_raw" ]]; then
                    dialog --msgbox "No ports specified. Returning to menu." 7 40
                    continue
                fi

                ports=$(parse_ports "$user_ports_raw")

                if [[ -z "$ports" ]]; then
                    dialog --msgbox "No valid ports specified." 7 40
                    continue
                fi

                # Process ports
                output=$(process_ports "add" "$ports" "$proto")
                dialog --title "Operation Log" --msgbox "$output" 15 60
                ;;
            4)
                # Protocol selection
                proto_choice=$(dialog --clear \
                    --title "Protocol" \
                    --menu "Select protocol:" 15 50 3 \
                    1 "TCP" \
                    2 "UDP" \
                    3 "TCP/UDP" \
                    3>&1 1>&2 2>&3)

                case $proto_choice in
                    1) proto="tcp" ;;
                    2) proto="udp" ;;
                    3) proto="both" ;;
                    *)
                        dialog --msgbox "No protocol selected. Returning to menu." 7 40
                        continue
                        ;;
                esac

                # Get ports from user
                user_ports_raw=$(dialog --inputbox "Enter ports or ranges (e.g., 80,443,2000-2010):" 10 50 3>&1 1>&2 2>&3)
                if [[ -z "$user_ports_raw" ]]; then
                    dialog --msgbox "No ports specified. Returning to menu." 7 40
                    continue
                fi

                ports=$(parse_ports "$user_ports_raw")

                if [[ -z "$ports" ]]; then
                    dialog --msgbox "No valid ports specified." 7 40
                    continue
                fi

                # Process ports
                output=$(process_ports "remove" "$ports" "$proto")
                dialog --title "Operation Log" --msgbox "$output" 15 60
                ;;
            5) show_ufw_rules ;;
            6) reset_ufw ;;
            7)
                preset_choice=$(dialog --menu "Select preset:" 15 60 7 \
                    1 "Web Server" \
                    2 "SSH Server" \
                    3 "FTP Server" \
                    4 "Mail Server" \
                    5 "DNS Server" \
                    6 "Game Server" \
                    7 "Cancel" 3>&1 1>&2 2>&3)

                case $preset_choice in
                    1) handle_preset "Web Server" ;;
                    2) handle_preset "SSH Server" ;;
                    3) handle_preset "FTP Server" ;;
                    4) handle_preset "Mail Server" ;;
                    5) handle_preset "DNS Server" ;;
                    6) handle_preset "Game Server" ;;
                    7) continue ;;
                    *) dialog --msgbox "No preset selected. Returning to menu." 7 40 ;;
                esac
                ;;
            8) OUTPUT=$(ufw status verbose); dialog --msgbox "$OUTPUT" 20 80 ;;
            0) break ;;
        esac
    done
}

# ==========================
# --- SYSTEM & UPDATES ---
# ==========================

# Function to get detailed system information
get_system_info() {
    # Get CPU information
    CPU_MODEL=$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo | xargs)
    CPU_CORES=$(lscpu | awk -F: '/^CPU\(s\)/ {print $2}' | xargs)
    CPU_SOCKET=$(lscpu | awk -F: '/Socket\(s\)/ {print $2}' | xargs)
    
    # Get CPU max frequency
    CPU_FREQ_MHZ=$(awk -F: '/cpu MHz/ {print $2; exit}' /proc/cpuinfo | xargs)
    CPU_FREQ_GHZ=$(awk "BEGIN {printf \"%.2f GHz\", $CPU_FREQ_MHZ/1000}")
    
    # Get memory information
    TOTAL_MEM=$(free -h | awk '/Mem:/ {print $2}')
    USED_MEM=$(free -h | awk '/Mem:/ {print $3}')
    AVAILABLE_MEM=$(free -h | awk '/Mem:/ {print $7}')
    SWAP_TOTAL=$(free -h | awk '/Swap:/ {print $2}')
    SWAP_USED=$(free -h | awk '/Swap:/ {print $3}')
    
    # Get disk information
    DISK_INFO=""
    DISK_COUNT=0
    while read -r disk; do
        if [ -n "$disk" ]; then
            DISK_NAME=$(echo "$disk" | awk '{print $1}')
            DISK_SIZE=$(echo "$disk" | awk '{print $2}')
            DISK_USED=$(echo "$disk" | awk '{print $3}')
            DISK_AVAIL=$(echo "$disk" | awk '{print $4}')
            DISK_PERCENT=$(echo "$disk" | awk '{print $5}')
            DISK_MOUNT=$(echo "$disk" | awk '{print $6}')
            
            DISK_INFO+="Device: $DISK_NAME\n"
            DISK_INFO+="  Size: $DISK_SIZE\n"
            DISK_INFO+="  Used: $DISK_USED ($DISK_PERCENT)\n"
            DISK_INFO+="  Available: $DISK_AVAIL\n"
            DISK_INFO+="  Mount point: $DISK_MOUNT\n\n"
            
            DISK_COUNT=$((DISK_COUNT + 1))
        fi
    done < <(df -h | grep -v "Filesystem\|tmpfs\|udev\|devtmpfs")
    
    # Get OS information
    OS_NAME=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    KERNEL_VERSION=$(uname -r)
    UPTIME=$(uptime -p)
    
    # Get network information
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    
    # Get system load average
    LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    
    # Get number of running processes
    PROCESS_COUNT=$(ps aux | wc -l)
    
    # Format the system information
    SYS_INFO="=== SYSTEM INFORMATION ===\n"
    SYS_INFO+="Operating System: $OS_NAME $OS_VERSION ($OS_CODENAME)\n"
    SYS_INFO+="Kernel Version: $KERNEL_VERSION\n"
    SYS_INFO+="Hostname: $HOSTNAME\n"
    SYS_INFO+="IP Address: $IP_ADDRESS\n"
    SYS_INFO+="System Uptime: $UPTIME\n"
    SYS_INFO+="Load Average: $LOAD_AVG\n"
    SYS_INFO+="Running Processes: $PROCESS_COUNT\n\n"
    
    SYS_INFO+="=== CPU INFORMATION ===\n"
    SYS_INFO+="Model: $CPU_MODEL @ $CPU_FREQ_GHZ\n"
    SYS_INFO+="vCores: $CPU_CORES\n"
    SYS_INFO+="Sockets: $CPU_SOCKET\n\n"
    
    SYS_INFO+="=== MEMORY INFORMATION ===\n"
    SYS_INFO+="Total Memory: $TOTAL_MEM\n"
    SYS_INFO+="Used Memory: $USED_MEM\n"
    SYS_INFO+="Available Memory: $AVAILABLE_MEM\n"
    SYS_INFO+="Total Swap: $SWAP_TOTAL\n"
    SYS_INFO+="Used Swap: $SWAP_USED\n\n"
    
    SYS_INFO+="=== DISK INFORMATION ===\n"
    SYS_INFO+="Number of Disks: $DISK_COUNT\n\n"
    SYS_INFO+="$DISK_INFO"
    
    echo -e "$SYS_INFO"
}


# ==========================
# --- REPOSITORY MANAGEMENT ---
# ==========================

list_repositories() {
    TEMP_FILE=$(mktemp)
    echo "=== /etc/apt/sources.list ===" > "$TEMP_FILE"
    grep -E "^\s*deb\s+" /etc/apt/sources.list >> "$TEMP_FILE"
    echo "" >> "$TEMP_FILE"

    if [ -d /etc/apt/sources.list.d ]; then
        for f in /etc/apt/sources.list.d/*.list; do
            [ -f "$f" ] || continue
            echo "=== $(basename "$f") ===" >> "$TEMP_FILE"
            grep -E "^\s*deb\s+" "$f" >> "$TEMP_FILE"
            echo "" >> "$TEMP_FILE"
        done
    fi

    cat "$TEMP_FILE"
    rm -f "$TEMP_FILE"
}

add_repository() {
    REPO_URL=$(dialog --inputbox "Enter repository URL (e.g., deb http://archive.ubuntu.com/ubuntu/ \$(lsb_release -cs)-proposed main):" 10 70 --stdout)
    [ -z "$REPO_URL" ] && return

    # Sprawdzenie, czy linia zaczyna się od 'deb'
    if [[ ! "$REPO_URL" =~ ^deb ]]; then
        dialog --msgbox "Invalid repository format. Must start with 'deb'." 7 60
        return
    fi

    # Sprawdzenie URL
    if [[ ! "$REPO_URL" =~ http ]] && [[ ! "$REPO_URL" =~ ftp ]]; then
        dialog --msgbox "Invalid repository format. Must include a URL (http or ftp)." 7 60
        return
    fi

    # Zamiana $(lsb_release -cs) na faktyczną nazwę kodową
    CODENAME=$(lsb_release -cs)
    REPO_URL=$(echo "$REPO_URL" | sed "s/\\\$\(lsb_release -cs\)/$CODENAME/g")

    REPO_FILE=$(dialog --inputbox "Enter filename for repository (e.g., my-repo.list) or leave blank for sources.list:" 10 50 --stdout)

    # Tworzenie backupu
    BACKUP_DIR="/var/backups/apt"
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d%H%M%S)

    if [ -z "$REPO_FILE" ]; then
        cp /etc/apt/sources.list "$BACKUP_DIR/sources.list.$TIMESTAMP.bak"
        echo "$REPO_URL" >> /etc/apt/sources.list
        dialog --msgbox "Repository added to /etc/apt/sources.list\nBackup at $BACKUP_DIR/sources.list.$TIMESTAMP.bak" 10 60
    else
        if [ -f "/etc/apt/sources.list.d/$REPO_FILE" ]; then
            cp "/etc/apt/sources.list.d/$REPO_FILE" "$BACKUP_DIR/$(basename "$REPO_FILE").$TIMESTAMP.bak"
        fi
        echo "$REPO_URL" >> "/etc/apt/sources.list.d/$REPO_FILE"
        dialog --msgbox "Repository added to /etc/apt/sources.list.d/$REPO_FILE\nBackup at $BACKUP_DIR/$(basename "$REPO_FILE").$TIMESTAMP.bak" 10 60
    fi

    dialog --infobox "Updating package lists..." 5 40
    apt-get update >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        dialog --msgbox "Repository added successfully." 7 50
    else
        dialog --msgbox "Repository added but error during update." 7 50
    fi
}


remove_repository() {
    REPOS=()
    FILES=()

    # Collect all repositories
    while read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        REPOS+=("$line")
    done < <(grep -hE "^\s*deb\s+" /etc/apt/sources.list /etc/apt/sources.list.d/*.list)

    [ ${#REPOS[@]} -eq 0 ] && { dialog --msgbox "No repositories found." 7 40; return; }

    MENU=()
    for i in "${!REPOS[@]}"; do
        SHORT=$(echo "${REPOS[$i]}" | cut -c1-60)
        MENU+=("$i" "$SHORT")
    done
    MENU+=("CANCEL" "Cancel")

    CHOICE=$(dialog --stdout --menu "Select repository to remove:" 20 80 15 "${MENU[@]}")
    [ -z "$CHOICE" ] || [ "$CHOICE" == "CANCEL" ] && return

    # Find which file contains it
    SEL_REPO="${REPOS[$CHOICE]}"
    FILE=$(grep -rlF "$SEL_REPO" /etc/apt/sources.list /etc/apt/sources.list.d/*.list)

    BACKUP_DIR="/var/backups/apt"
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    cp "$FILE" "$BACKUP_DIR/$(basename "$FILE").$TIMESTAMP.bak"

    # Delete the line
    sed -i "\|$SEL_REPO|d" "$FILE"

    # Remove empty file
    [ ! -s "$FILE" ] && rm -f "$FILE"

    dialog --infobox "Updating package list..." 5 40
    apt-get update -qq
    dialog --msgbox "Repository removed successfully." 7 40
}


# System menu
system_menu() {
    while true; do
        CHOICE=$(dialog --clear --stdout --title "System & Updates" \
            --menu "Select option:" 15 60 6 \
            1 "Update & Upgrade" \
            2 "Repository Management" \
            3 "System Information" \
            0 "Back")
        case $CHOICE in
            1)
                apt-get update -qq >/dev/null 2>&1;
                apt-get upgrade -y -qq >/dev/null 2>&1
                dialog --msgbox "System updated successfully" 7 40 ;;
            2)
                while true; do
                    REPO_CHOICE=$(dialog --clear --stdout --title "Repository Management" \
                        --menu "Select option:" 15 60 5 \
                        1 "List Repositories" \
                        2 "Add Repository" \
                        3 "Remove Repository" \
                        0 "Back")
                    case $REPO_CHOICE in
                        1)
                            REPO_INFO=$(list_repositories)
                            dialog --title "Repository List" --msgbox "$REPO_INFO" 20 80 ;;
                        2)
                            add_repository
                            # Show updated list after adding
                            REPO_INFO=$(list_repositories)
                            dialog --title "Updated Repository List" --msgbox "$REPO_INFO" 20 80 ;;
                        3)
                            remove_repository
                            # Show updated list after removing
                            REPO_INFO=$(list_repositories)
                            dialog --title "Updated Repository List" --msgbox "$REPO_INFO" 20 80 ;;
                        0) break ;;
                    esac
                done ;;
            3)
                SYS_INFO=$(get_system_info)
                dialog --title "System Information" --msgbox "$SYS_INFO" 25 80 ;;
            0) break ;;
        esac
    done
}

# ==========================
# --- APPLICATIONS --- 
# ==========================

APP_DIR="./modules"
GITHUB_REPO="https://github.com/yourusername/yourrepo" # Podmień na swoje repo z addonami

# Funkcja sprawdzająca czy pakiet jest zainstalowany
is_installed() {
    dpkg -l "$1" 2>/dev/null | awk '/^ii/ {print $2}' | grep -q "^$1"
}

# Funkcja pobierająca wszystkie addony z GitHub
fetch_addons() {
    TMP_DIR=$(mktemp -d)
    ZIP_URL="https://github.com/Vahistar/BiteHost-vpsTOOLKIT/archive/refs/heads/main.zip"

    curl -sL "$ZIP_URL" -o "$TMP_DIR/addons.zip"
    mkdir -p "$APP_DIR"
    unzip -o "$TMP_DIR/addons.zip" -d "$TMP_DIR/" >/dev/null 2>&1

    if [ -d "$TMP_DIR"/BiteHost-vpsTOOLKIT-*/modules ]; then
        cp -rf "$TMP_DIR"/BiteHost-vpsTOOLKIT-*/modules/* "$APP_DIR"/
        sed -i 's/\r//' "$APP_DIR"/*.bitehost 2>/dev/null
        chmod +x "$APP_DIR"/*.bitehost 2>/dev/null
        dialog --msgbox "Addons have been downloaded." 7 50
    else
        dialog --msgbox "No modules directory found in archive." 7 50
    fi

    rm -rf "$TMP_DIR"
}

# Załaduj wszystkie pliki z katalogu apps
for f in "$APP_DIR"/*.bitehost; do
    [ -f "$f" ] && source "$f"
done

# Menu główne aplikacji
app_menu() {
    while true; do
        MENU=()
        for f in "$APP_DIR"/*.bitehost; do
            [ -f "$f" ] || continue
            source "$f"  # deklaracja funkcji i zmiennych

            if is_installed "$APP_NAME"; then
                STATUS="INSTALLED (Manage)"
            else
                STATUS="NOT INSTALLED"
            fi
            MENU+=("$APP_NAME" "$STATUS")
        done
        MENU+=("Fetch_Addons" "Download all addons from GitHub")
        MENU+=("0" "Back")

        APP=$(dialog --clear --stdout --menu "Select application:" 20 70 15 "${MENU[@]}")
        [ -z "$APP" ] && continue
        [ "$APP" == "0" ] && break

        if [ "$APP" == "Fetch_Addons" ]; then
            fetch_addons
            continue
        fi

        # Wywołanie funkcji tylko dla wybranej aplikacji
        for f in "$APP_DIR"/*.bitehost; do
            [ -f "$f" ] || continue
            source "$f"
            if [ "$APP" == "$APP_NAME" ]; then
                if ! is_installed "$APP_NAME"; then
                    DEBIAN_FRONTEND=noninteractive apt-get install -y $APP_NAME > /dev/null 2>&1
                    dialog --msgbox "$APP_NAME został zainstalowany automatycznie." 7 50
                fi
                manage_app
                break
            fi
        done

    done
}

# Napraw CRLF i ustaw prawa wykonywalności dla wszystkich addonów
sed -i 's/\r//' "$APP_DIR"/*.bitehost
chmod +x "$APP_DIR"/*.bitehost


# Uruchom menu
# app_menu



# app_menu() {
#     APPS=("nginx" "docker" "postgresql")

#     is_installed() {
#         # Sprawdza, czy jakakolwiek paczka zaczyna się od nazwy
#         dpkg -l | awk '{print $2}' | grep -q "^$1"
#     }

#     while true; do
#         MENU=()
#         for a in "${APPS[@]}"; do
#             if is_installed "$a"; then
#                 STATUS="INSTALLED (Manage)"
#             else
#                 STATUS="NOT INSTALLED"
#             fi
#             MENU+=("$a" "$STATUS")
#         done
#         MENU+=("0" "Back")
#         APP=$(dialog --clear --stdout --menu "Select application:" 20 70 10 "${MENU[@]}")
#         [ -z "$APP" ] && continue
#         [ "$APP" == "0" ] && break

#         case $APP in
#             "nginx")
#                 if is_installed nginx; then
#                     SERVICE_STATUS=$(systemctl is-active nginx 2>/dev/null)
#                     INSTALLED_VER=$(dpkg -s nginx | awk '/Version:/ {print $2}')
#                     LATEST_VER=$(apt-cache policy nginx | awk '/Candidate:/ {print $2}')
#                     ACTION=$(dialog --clear --stdout --title "Nginx Management" \
#                         --menu "Status: $SERVICE_STATUS\nInstalled: $INSTALLED_VER\nLatest: $LATEST_VER" 20 70 10 \
#                         1 "Start" 2 "Stop" 3 "Restart" 4 "Update" 5 "Check for Updates" 6 "Uninstall" 0 "Back")

#                     case $ACTION in
#                         1) systemctl start nginx > /dev/null 2>&1; dialog --msgbox "Nginx started." 7 40 ;;
#                         2) systemctl stop nginx > /dev/null 2>&1; dialog --msgbox "Nginx stopped." 7 40 ;;
#                         3) systemctl restart nginx > /dev/null 2>&1; dialog --msgbox "Nginx restarted." 7 40 ;;
#                         4) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade nginx > /dev/null 2>&1; dialog --msgbox "Nginx updated." 7 40 ;;
#                         5) apt-get update -qq > /dev/null 2>&1; NEW_VER=$(apt-cache policy nginx | awk '/Candidate:/ {print $2}'); dialog --msgbox "Latest version: $NEW_VER" 7 40 ;;
#                         6) DEBIAN_FRONTEND=noninteractive apt-get purge -y nginx > /dev/null 2>&1; apt-get autoremove -y > /dev/null 2>&1; dialog --msgbox "Nginx uninstalled." 7 40 ;;
#                     esac
#                 else
#                     DEBIAN_FRONTEND=noninteractive apt-get install -y nginx > /dev/null 2>&1
#                     dialog --msgbox "Nginx installed." 7 40
#                 fi
#                 ;;

#             "docker")
#                 if is_installed docker-ce; then
#                     INSTALLED_VER=$(dpkg -s docker-ce | awk '/Version:/ {print $2}')
#                     LATEST_VER=$(apt-cache policy docker-ce | awk '/Candidate:/ {print $2}')
#                     SERVICE_STATUS=$(systemctl is-active docker 2>/dev/null)
#                     BUILDX_VER=$(dpkg -s docker-buildx-plugin 2>/dev/null | awk '/Version:/ {print $2}' || echo "Not installed")
#                     COMPOSE_VER=$(dpkg -s docker-compose-plugin 2>/dev/null | awk '/Version:/ {print $2}' || echo "Not installed")

#                     ACTION=$(dialog --clear --stdout --title "Docker Management" \
#                         --menu "Docker CE: $INSTALLED_VER (Latest: $LATEST_VER)\nService: $SERVICE_STATUS\nBuildx: $BUILDX_VER\nCompose: $COMPOSE_VER" 20 80 12 \
#                         1 "Start Docker" 2 "Stop Docker" 3 "Restart Docker" 4 "Update Docker" 5 "Check for Updates" 6 "Uninstall Docker" 0 "Back")

#                     case $ACTION in
#                         1) systemctl start docker > /dev/null 2>&1; dialog --msgbox "Docker started." 7 40 ;;
#                         2) systemctl stop docker > /dev/null 2>&1; dialog --msgbox "Docker stopped." 7 40 ;;
#                         3) systemctl restart docker > /dev/null 2>&1; dialog --msgbox "Docker restarted." 7 40 ;;
#                         4) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras > /dev/null 2>&1; dialog --msgbox "Docker updated." 7 40 ;;
#                         5) apt-get update -qq > /dev/null 2>&1; NEW_VER=$(apt-cache policy docker-ce | awk '/Candidate:/ {print $2}'); dialog --msgbox "Latest version: $NEW_VER" 7 40 ;;
#                         6) DEBIAN_FRONTEND=noninteractive apt-get purge -y docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras > /dev/null 2>&1; apt-get autoremove -y > /dev/null 2>&1; dialog --msgbox "Docker uninstalled." 7 40 ;;
#                     esac
#                 else
#                     DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras > /dev/null 2>&1
#                     dialog --msgbox "Docker installed." 7 40
#                 fi
#                 ;;

#             "postgresql")
#                 if dpkg -l | grep -q '^ii  postgresql'; then
#                     SERVICE_STATUS=$(systemctl is-active postgresql 2>/dev/null)
#                     INSTALLED_VER=$(dpkg -s postgresql | awk '/Version:/ {print $2}')
#                     LATEST_VER=$(apt-cache policy postgresql | awk '/Candidate:/ {print $2}')
#                     ACTION=$(dialog --clear --stdout --title "PostgreSQL Management" \
#                         --menu "Status: $SERVICE_STATUS\nInstalled: $INSTALLED_VER\nLatest: $LATEST_VER" 20 70 10 \
#                         1 "Start" 2 "Stop" 3 "Restart" 4 "Update" 5 "Check for Updates" 6 "Uninstall" 0 "Back")

#                     case $ACTION in
#                         1) systemctl start postgresql > /dev/null 2>&1; dialog --msgbox "PostgreSQL started." 7 40 ;;
#                         2) systemctl stop postgresql > /dev/null 2>&1; dialog --msgbox "PostgreSQL stopped." 7 40 ;;
#                         3) systemctl restart postgresql > /dev/null 2>&1; dialog --msgbox "PostgreSQL restarted." 7 40 ;;
#                         4) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade postgresql > /dev/null 2>&1; dialog --msgbox "PostgreSQL updated." 7 40 ;;
#                         5) apt-get update -qq > /dev/null 2>&1; NEW_VER=$(apt-cache policy postgresql | awk '/Candidate:/ {print $2}'); dialog --msgbox "Latest version: $NEW_VER" 7 40 ;;
#                         6) DEBIAN_FRONTEND=noninteractive apt-get purge -y postgresql* > /dev/null 2>&1; apt-get autoremove -y > /dev/null 2>&1; dialog --msgbox "PostgreSQL uninstalled." 7 40 ;;
#                     esac
#                 else
#                     DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql > /dev/null 2>&1
#                     dialog --msgbox "PostgreSQL installed." 7 40
#                 fi
#                 ;;
#         esac
#     done
# }



# ==========================
# MAIN MENU
# ==========================
while true; do
    CHOICE=$(dialog --clear --stdout --title "VPS Toolkit" \
        --menu "Select category:" 20 60 10 \
        1 "User Management" \
        2 "Firewall (ufw)" \
        3 "System & Updates" \
        4 "Applications" \
        0 "Exit")
    case $CHOICE in
        1) user_menu ;;
        2) firewall_menu ;;
        3) system_menu ;;
        4) app_menu ;;
        0) clear; exit ;;
    esac
done
