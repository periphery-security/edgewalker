# Risk Scoring

Each device is scored using a three-pillar weighted model. The network gets an overall grade based on the worst device.

## Category Weights

| Category | Weight | What It Measures |
|---|---|---|
| Exposure | 25% | Open ports and their risk level |
| Credentials | 40% | Default passwords found |
| Vulnerabilities | 35% | Known CVEs in running software |

Credentials are weighted highest because a device with default passwords is trivially compromisable — no exploit needed.

## How Scores Are Calculated

Each category is scored 0-100 using **worst-case + diminishing extras**:

1. Start with the severity of the worst finding
2. Add a small penalty for each additional finding
3. Cap at 100

### Port Severity

| Port | Service | Score |
|---|---|---|
| 23 | Telnet | 80 |
| 5900 | VNC | 70 |
| 21 | FTP | 60 |
| 22 | SSH | 30 |
| Other | — | 10 |

Each additional open port adds +3.

### Credential Severity

| Service | Score |
|---|---|
| Telnet | 100 |
| FTP | 90 |
| SMB | 85 |
| SSH | 80 |

Each additional finding adds +5.

### CVE Severity

| Rating | Score |
|---|---|
| CRITICAL | 100 |
| HIGH | 75 |
| MEDIUM | 50 |
| LOW | 25 |

Each additional CVE adds +5.

## Final Score

```
score = (exposure × 0.25) + (credentials × 0.40) + (vulnerabilities × 0.35)
```

## Risk Levels

| Score | Level |
|---|---|
| 80-100 | CRITICAL |
| 50-79 | HIGH |
| 25-49 | MEDIUM |
| 1-24 | LOW |
| 0 | NONE |

## Network Grade

The grade is determined by the worst finding across all devices:

| Grade | Meaning |
|---|---|
| **A+** | Your network is perfectly secure. No issues found. |
| **A** | All devices low risk or clean |
| **B** | Medium risk devices present |
| **C** | High risk device on network |
| **D** | Critical risk device on network |
| **F** | Default credentials found — network is trivially compromisable |

A single device with default credentials gives the entire network an F.
