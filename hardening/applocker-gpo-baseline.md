# Post-Incident Hardening Baseline — Terra Case

Controls derived directly from the gaps exploited during the incident.
Each control references the ATT&CK technique it neutralizes.

## 1. Email (T1566.001)

| Control | Implementation | Status |
|---|---|---|
| SPF | TXT record with `-all` (hard fail) policy | Pending |
| DKIM | Sign all outbound mail, rotate keys every six months | Pending |
| DMARC | `p=reject; rua=mailto:dmarc@<domain>` after 30 days at `p=none` | Pending |
| Lookalike domains | Monitor and block typosquatted domains (`outluok.co`) | Pending |
| External banner | Visible warning on every message originating outside the organization | Pending |

## 2. Endpoint — AppLocker / WDAC (T1204.002, T1059.001)

`Deny` rules for the `Everyone` group, with explicit exceptions for
administrators and signed paths:

```
%OSDRIVE%\Users\*\AppData\Local\Temp\*
%OSDRIVE%\Users\*\AppData\Roaming\*
%OSDRIVE%\Users\*\Downloads\*
%OSDRIVE%\$Recycle.Bin\*
```

Additional blocking by hash and by name for dual-use tooling:

| Tool | Known hash |
|---|---|
| `nc.exe` | `b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c` |
| `ncat.exe`, `psexec.exe`, `nmap.exe` | Block by publisher name |

> Deploy in **Audit Only** mode for 2–4 weeks first, to inventory the legitimate
> software that runs from those paths. Switch to Enforce afterwards.

## 3. File Extensions (T1036.003)

`Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> File Explorer`

Disable *"Hide extensions for known file types"*. A zero-cost control that
directly neutralizes the `.pdf.exe` double extension.

## 4. GPO-Managed Firewall (T1562.001)

`Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Windows Defender Firewall with Advanced Security`

- Domain, Private and Public profiles forced to **On**.
- Local users cannot modify them; the policy is reasserted on every GPO refresh.
- SIEM alert on any modification attempt (see `detections/04-*.eql`).

## 5. PowerShell (T1059.001)

| Control | Detail |
|---|---|
| Constrained Language Mode | Applied to standard users via AppLocker |
| Script Block Logging | Event ID **4104** — enabled and forwarded to the SIEM |
| Module Logging | Event ID **4103** |
| Transcription | Output to a centralized write-only share |
| ExecutionPolicy | `AllSigned` (not a security boundary on its own, but raises attacker cost) |

## 6. Identity (T1136.001, T1078.003)

- Immediate alert on local account creation across endpoints (`detections/01-*.eql`).
- Periodic review of `Administrators` group membership on every host.
- LAPS or equivalent for the local administrator account.

## 7. Awareness

Quarterly phishing simulations focused on the two vectors that worked in this
incident: **artificial urgency** and **double extensions**.
Target metrics: click rate below 5%, report rate above 60%.
