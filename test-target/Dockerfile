# Stage 1: Base image with required packages
FROM alpine:3.14 AS base

# Install services and utilities
# - OpenSSH 8.6p1 (CVE-2021-41617, CVE-2020-14145)
# - vsftpd 3.0.4 (CVE-2021-3618 ALPACA)
# - busybox telnetd (minimal)
# - Samba 4.14.14 (CVE-2021-44142, CVE-2022-45141)
RUN apk add --no-cache \
    openssh-server \
    vsftpd \
    busybox-extras \
    linux-pam \
    samba \
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

# Stage 3: Final Runtime Image
FROM base

# Copy configurations and user data from setup stage
COPY --from=setup /etc/passwd /etc/passwd
COPY --from=setup /etc/group /etc/group
COPY --from=setup /etc/shadow /etc/shadow
COPY --from=setup /etc/ssh /etc/ssh
COPY --from=setup /etc/samba /etc/samba
COPY --from=setup /var/lib/samba /var/lib/samba
COPY --from=setup /var/run /var/run
COPY --from=setup /var/log /var/log
COPY --from=setup /srv/share /srv/share
COPY --from=setup /var/ftp /var/ftp

# Copy configuration files and startup script
COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY smb.conf /etc/samba/smb.conf
COPY start.sh /start.sh

# Fix permissions
RUN chmod +x /start.sh

# Expose ports
EXPOSE 21 22 23 445

CMD ["/start.sh"]
