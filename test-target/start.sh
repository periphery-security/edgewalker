#!/bin/sh
# Start all services for EdgeWalker testing

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

echo "==========================================="
echo " EdgeWalker Test Target"
echo "==========================================="
echo "  SSH:      port 22   (root:alpine, admin:password)"
echo "  FTP:      port 21   (ftp:ftp, admin:password)"
echo "  Telnet:   port 23   (admin:password)"
echo "  SMB:      port 445  (admin:password, guest:)"
echo "  HTTP:     port 80"
echo "  HTTPS:    port 443  (Expired Cert)"
echo "  MySQL:    port 3306 (root:no password)"
echo "  Postgres: port 5432 (postgres:trust)"
echo "  Redis:    port 6379 (anonymous)"
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

# Start Nginx
mkdir -p /run/nginx
/usr/sbin/nginx
printf "  ${GREEN}[OK]${RESET} nginx\n"

# Start Redis
redis-server /etc/redis.conf &
printf "  ${GREEN}[OK]${RESET} redis\n"

# Start PostgreSQL
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql
su postgres -c "pg_ctl start -D /var/lib/postgresql/data"
printf "  ${GREEN}[OK]${RESET} postgres\n"

# Start MariaDB/MySQL and configure root access
/usr/bin/mysqld_safe --datadir='/var/lib/mysql' --bind-address=0.0.0.0 &
# Wait for MariaDB to start
for i in 1 2 3 4 5 6 7 8 9 10; do
    if mysqladmin ping >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
# Robustly allow root from any host with no password
mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '';
CREATE USER IF NOT EXISTS 'root'@'%';
SET PASSWORD FOR 'root'@'%' = PASSWORD('');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
printf "  ${GREEN}[OK]${RESET} mariadb\n"

echo "-------------------------------------------"
echo "All services running. Watching logs..."
echo "==========================================="

# Tail all log files
touch /var/log/messages /var/log/vsftpd.log /var/log/samba/smb.log

tail -F /var/log/messages /var/log/vsftpd.log /var/log/samba/smb.log 2>/dev/null | \
awk '
  /OK LOGIN|Accepted password|Login successful|230 Login|authentication for user.*succeeded/ {
    printf "\033[32m%s\033[0m\n", $0; next
  }
  /FAIL LOGIN|authentication failure|invalid password|Login incorrect|530 Login|FAILED with error|login failed/ {
    printf "\033[31m%s\033[0m\n", $0; next
  }
  /CONNECT|Connection closed|Connection from/ {
    printf "\033[33m%s\033[0m\n", $0; next
  }
  { print }
' &

# Keep container alive and monitor services
while true; do
    sleep 30

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

    if ! pgrep nginx > /dev/null; then
        echo "[WARN] nginx died, restarting..."
        /usr/sbin/nginx
    fi

    if ! pgrep redis-server > /dev/null; then
        echo "[WARN] redis died, restarting..."
        redis-server /etc/redis.conf &
    fi

    if ! su postgres -c "pg_isready" > /dev/null; then
        echo "[WARN] postgres died, restarting..."
        su postgres -c "pg_ctl start -D /var/lib/postgresql/data"
    fi

    if ! pgrep mysqld > /dev/null; then
        echo "[WARN] mariadb died, restarting..."
        /usr/bin/mysqld_safe --datadir='/var/lib/mysql' &
    fi
done
