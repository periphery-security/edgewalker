# EdgeWalker Test Target

Vulnerable Docker container for testing the EdgeWalker scanner locally.

## Services

| Service | Port | Credentials |
|---------|------|-------------|
| OpenSSH 8.6p1 | 22 | `root:alpine`, `admin:password` |
| vsftpd 3.0.4 | 21 | `ftp:ftp`, `admin:password` |
| Telnet (busybox) | 23 | `admin:password` |
| Samba 4.14 | 445 | `admin:password`, `guest:` (no password) |

## Usage

```bash
# Build and run
docker compose up -d --build

# Watch logs (connections, login attempts)
docker logs -f edgewalker-target

# Stop
docker compose down
```

## Logs

All service logs are streamed to stdout via `docker logs`:
- Successful logins are highlighted in green
- Failed logins are highlighted in red
- Connections are highlighted in yellow
