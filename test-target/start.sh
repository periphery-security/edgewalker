#!/bin/sh
# Start all services for EdgeWalker testing

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

echo "==========================================="
echo " EdgeWalker Test Target"
echo "==========================================="
echo "  SSH:    port 22  (root:alpine, admin:password)"
echo "  FTP:    port 21  (ftp:ftp, admin:password)"
echo "  Telnet: port 23  (admin:password)"
echo "  SMB:    port 445 (admin:password, guest:)"
echo "-------------------------------------------"

# Start syslogd so SSH and telnet auth events get captured
syslogd -n -O /var/log/messages &
printf "  ${GREEN}[OK]${RESET} syslogd\n"

# Start SSH (runs in background by default)
/usr/sbin/sshd
printf "  ${GREEN}[OK]${RESET} sshd\n"

# Start telnetd (busybox)
telnetd -F -l /bin/login &
printf "  ${GREEN}[OK]${RESET} telnetd\n"

# Start vsftpd in background
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
printf "  ${GREEN}[OK]${RESET} vsftpd\n"

# Start Samba (smbd for file sharing on port 445)
/usr/sbin/smbd --no-process-group &
printf "  ${GREEN}[OK]${RESET} smbd\n"

echo "-------------------------------------------"
echo "All services running. Watching logs..."
echo "==========================================="

# Tail all log files and colorize: green for successful logins, red for failures
# Ensure log files exist so tail -F can follow them from the start
touch /var/log/messages /var/log/vsftpd.log /var/log/samba/smb.log

tail -F /var/log/messages /var/log/vsftpd.log /var/log/samba/smb.log 2>/dev/null | \
awk '
  # Skip noisy samba internal lines
  /GENSEC backend|gensec_register|ntlmssp_util|neg_flags/ { next }
  # Green: successful logins
  /OK LOGIN|Accepted password|Login successful|230 Login|authentication for user.*succeeded/ {
    printf "\033[32m%s\033[0m\n", $0; next
  }
  # Red: failed logins
  /FAIL LOGIN|authentication failure|invalid password|Login incorrect|530 Login|FAILED with error|login failed/ {
    printf "\033[31m%s\033[0m\n", $0; next
  }
  # Yellow: connections
  /CONNECT|Connection closed|Connection from/ {
    printf "\033[33m%s\033[0m\n", $0; next
  }
  { print }
' &

# Keep container alive and monitor services
while true; do
    sleep 30

    # Check if services are still running, restart if needed
    if ! pgrep sshd > /dev/null; then
        echo "[WARN] sshd died, restarting..."
        /usr/sbin/sshd
    fi

    if ! pgrep vsftpd > /dev/null; then
        echo "[WARN] vsftpd died, restarting..."
        /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
    fi

    if ! pgrep telnetd > /dev/null; then
        echo "[WARN] telnetd died, restarting..."
        telnetd -F -l /bin/login &
    fi

    if ! pgrep smbd > /dev/null; then
        echo "[WARN] smbd died, restarting..."
        /usr/sbin/smbd --no-process-group &
    fi
done
