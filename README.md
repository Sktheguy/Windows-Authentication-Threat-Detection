\# Windows Authentication Threat Detection



\## Project Overview



A PowerShell-based security monitoring project designed to detect potential brute-force authentication activity using Windows Security Event ID 4625.



The detector analyses failed logon events, groups them by targeted account and identifies repeated failures within a configurable time window.



It supports both live Windows Security log analysis and simulated authentication events for safe testing.



\## Objectives



\- Investigate Windows authentication events.

\- Develop a configurable brute-force detection rule.

\- Implement PowerShell-based security event analysis.

\- Validate detection logic using simulated events.

\- Export structured alerts to CSV.

\- Document detection results and limitations.



\## Technologies



\- Windows Security Event Logs

\- Windows Event IDs 4624 and 4625

\- PowerShell

\- Windows Event Viewer

\- CSV reporting



\## Detection Logic



Default detection parameters:



\- Event ID: 4625 — Failed Logon

\- Threshold: 5 failed authentication attempts

\- Detection window: 5 minutes

\- Grouping: Target account

\- Initial severity: Medium



The detector uses a sliding time window to identify repeated authentication failures.



An alert represents potentially suspicious activity requiring investigation, not proof of a successful attack.



\## Operating Modes



\### Simulation Mode



Runs controlled, in-memory authentication events without generating real failed logons or modifying Windows Security logs.



```powershell

.\\SOC-Logon-Detector.ps1 -TestMode

```



\### Live Mode



Queries the Windows Security log for actual Event ID 4625 records.



```powershell

.\\SOC-Logon-Detector.ps1 -LookbackHours 24 -Threshold 5 -WindowMinutes 5

```



Live mode may require an elevated PowerShell session or appropriate Security log read permissions.



\## Alert Reporting



When a detection threshold is reached, the script exports a structured CSV report containing:



\- Detection timestamp

\- First and last failed authentication timestamps

\- Target account

\- Failed attempt count

\- Recorded source IP addresses

\- Severity

\- Detection rule

\- Data source (LIVE or SIMULATION)



\## Validation Results



The detection logic was tested against several simulated scenarios:



| Test | Expected Result | Outcome |

|---|---|---|

| Seven failures within five minutes | Alert | Passed |

| Three failures within five minutes | No alert | Passed |

| Five failures spread over twenty minutes | No alert | Passed |

| Failures distributed across multiple accounts | No alert | Passed |

| Saved detector simulation | Alert | Passed |

| Automatic CSV export | Report generated | Passed |

| Live log collection with no matching events | NO DATA | Passed |



The initial negative scenarios were validated during interactive PowerShell testing. The saved script's current TestMode generates the positive seven-failure scenario.



\## Limitations



\- The detector runs on demand; it does not continuously monitor authentication events.

\- Detection groups events by account rather than by account and source IP.

\- Repeated execution against the same events may generate duplicate reports.

\- Source IP information may be absent for certain Windows logon types.

\- A threshold-based alert may include legitimate authentication failures.

\- The simulation tests detection logic but does not establish end-to-end detection of a real attack.



\## Future Improvements



\- Continuous event monitoring

\- Source IP correlation

\- Alert deduplication

\- Severity scoring

\- SIEM integration

\- Automated regression testing



\## Security and Privacy



All public sample alerts should use simulated or anonymised data. Real Windows authentication logs may contain sensitive account and network information.



\## Project Classification



Cybersecurity Portfolio — SOC Analyst Level 1



\*\*Status:\*\* Functional prototype with validated simulation and live log-query capabilities.

