# Stage 1: Base image with required packages
FROM alpine:3.14 AS base

# Install services and utilities
RUN apk add --no-cache \
    openssh-server \
    vsftpd \
    busybox-extras \
    linux-pam \
    samba \
    nginx \
    openssl \
    redis \
    postgresql \
    mariadb \
    mariadb-client \
    && rm -rf /var/cache/apk/*

# Stage 2: Configuration and Setup
FROM base AS setup

# Create test users with weak credentials
RUN echo "root:alpine" | chpasswd && \
    adduser -D -s /bin/sh admin && \
    echo "admin:password" | chpasswd && \
    echo "ftp:ftp" | chpasswd

# Configure SSH - allow root login with password
RUN ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

# Configure vsftpd for local user auth
RUN mkdir -p /var/ftp /var/run/vsftpd/empty /var/log && \
    chown ftp:ftp /var/ftp && \
    touch /var/log/vsftpd.log

# Configure Samba - open share with default creds
RUN mkdir -p /srv/share /var/log/samba /var/lib/samba/private /var/run/samba && \
    chmod 777 /srv/share && \
    echo "EdgeWalker SMB test target" > /srv/share/README.txt

# Set Samba password for admin user
RUN printf "password\npassword\n" | smbpasswd -a -s admin && \
    (smbpasswd -a -s guest < /dev/null || true)

# Configure Vulnerable Web Server
RUN mkdir -p /var/www/localhost/html/.git && \
    echo "DB_PASSWORD=supersecret" > /var/www/localhost/html/.env && \
    echo "[core]\n\trepositoryformatversion = 0" > /var/www/localhost/html/.git/config && \
    echo "<h1>EdgeWalker Vulnerable Web Target</h1>" > /var/www/localhost/html/index.html && \
    chown -R nginx:nginx /var/www/localhost/html

# Generate SSL Certificate (Valid for 365 days)
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=US/ST=State/L=City/O=EdgeWalker/OU=Test/CN=localhost"

# Configure Vulnerable Redis (Anonymous access)
RUN sed -i 's/bind 127.0.0.1/bind 0.0.0.0/' /etc/redis.conf && \
    sed -i 's/protected-mode yes/protected-mode no/' /etc/redis.conf

# Configure Vulnerable PostgreSQL (Trust authentication)
RUN mkdir -p /var/lib/postgresql/data && \
    chown -R postgres:postgres /var/lib/postgresql && \
    su postgres -c "initdb -D /var/lib/postgresql/data" && \
    echo "host all all 0.0.0.0/0 trust" > /var/lib/postgresql/data/pg_hba.conf && \
    echo "listen_addresses='*'" >> /var/lib/postgresql/data/postgresql.conf

# Configure Vulnerable MariaDB/MySQL (Root with no password, listen on all IPs)
RUN mysql_install_db --user=mysql --datadir=/var/lib/mysql && \
    mkdir -p /run/mysqld && chown -R mysql:mysql /run/mysqld /var/lib/mysql && \
    echo -e "[mysqld]\nskip-networking=0\nbind-address=0.0.0.0\nskip-name-resolve" > /etc/my.cnf.d/vulnerable.cnf

# Stage 3: Final Runtime Image
FROM base

# Copy configurations and user data from setup stage
COPY --from=setup /etc/passwd /etc/passwd
COPY --from=setup /etc/group /etc/group
COPY --from=setup /etc/shadow /etc/shadow
COPY --from=setup /etc/ssh /etc/ssh
COPY --from=setup /etc/samba /etc/samba
COPY --from=setup /etc/nginx /etc/nginx
COPY --from=setup /etc/redis.conf /etc/redis.conf
COPY --from=setup /etc/my.cnf.d/vulnerable.cnf /etc/my.cnf.d/vulnerable.cnf
COPY --from=setup /var/lib/postgresql/data /var/lib/postgresql/data
COPY --from=setup /var/lib/mysql /var/lib/mysql
COPY --from=setup /var/lib/samba /var/lib/samba
COPY --from=setup /var/run /var/run
COPY --from=setup /var/log /var/log
COPY --from=setup /srv/share /srv/share
COPY --from=setup /var/ftp /var/ftp
COPY --from=setup /var/www/localhost/html /var/www/localhost/html

# Copy configuration files and startup script
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY smb.conf /etc/samba/smb.conf
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY start.sh /start.sh

# Fix permissions
RUN chmod +x /start.sh && \
    chown -R postgres:postgres /var/lib/postgresql/data && \
    chmod 700 /var/lib/postgresql/data && \
    mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql && \
    chown -R mysql:mysql /var/lib/mysql && \
    mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld

# Expose ports
EXPOSE 21 22 23 445 80 443 3306 5432 6379

CMD ["/start.sh"]
