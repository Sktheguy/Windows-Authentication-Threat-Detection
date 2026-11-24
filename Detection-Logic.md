# Detection Logic — Windows Authentication Threat Detection



## 1. Detection Objective



Identify potentially suspicious patterns of repeated failed Windows authentication attempts using Windows Security Event ID 4625.



The detector is designed as an introductory SOC detection engineering project. It highlights authentication patterns that warrant further investigation rather than automatically confirming malicious activity.



## 2. Data Sources



*\*Live Mode:\*\* Windows Security Event Log, collected through PowerShell `Get-WinEvent`.



*\*Simulation Mode:\*\* In-memory PowerShell objects representing failed authentication events.



Each normalised event contains:



| Field | Description |

|---|---|

| TimeCreated | Authentication failure timestamp |

| EventID | Windows event identifier, 4625 |

| Account | Targeted account |

| SourceIP | Source IP address, where recorded |



Live event fields are extracted from Windows Event XML, including `TargetDomainName`, `TargetUserName` and `IpAddress`.



## 3. Detection Parameters



| Parameter | Default | Purpose |

|---|---|---|

| LookbackHours | 24 | Historical period searched in Live Mode |

| Threshold | 5 | Minimum failures needed to trigger an alert |

| WindowMinutes | 5 | Sliding detection window |

| TestMode | Disabled | Enables synthetic event testing |



The threshold and window are configurable.



## 4. Sliding-Window Detection Algorithm



The detector:



1\. Collects authentication failure events.

2\. Groups events by targeted account.

3\. Sorts each account's events chronologically.

4\. Examines the preceding detection window for each event.

5\. Counts failures within that window, including the current event.

6\. Generates an alert when the configured threshold is reached.

7\. Stops after the first qualifying window for that account during the execution.

8\. Exports the alert to CSV.



### Example



Five failed logons against `SOC-LAB-USER`:



| Time | Account | Event ID |

|---|---|---|

| 10:00:00 | SOC-LAB-USER | 4625 |

| 10:00:30 | SOC-LAB-USER | 4625 |

| 10:01:00 | SOC-LAB-USER | 4625 |

| 10:01:30 | SOC-LAB-USER | 4625 |

| 10:02:00 | SOC-LAB-USER | 4625 |



*\*Result:\*\* Alert generated because five failures occurred within five minutes.



### Detection pseudocode



```text

FOR EACH account:

&#x20;   Sort failed logons by timestamp



&#x20;   FOR EACH event:

&#x20;       Define window ending at event timestamp

&#x20;       Count failures inside the window



&#x20;       IF count >= threshold:

&#x20;           Generate alert

&#x20;           Stop evaluating that account

```



## 5. Alert Generation



An alert contains:



- DetectionTime

- FirstFailure

- LastFailure

- Account

- FailedAttempts

- SourceIPs

- Severity

- DetectionRule

- DataSource



The prototype assigns \*\*Medium\*\* severity to threshold-matching activity.



SourceIPs contains the distinct, non-empty source addresses associated with the triggering window. The detector does not currently require those failures to originate from the same IP address.



The DetectionRule field dynamically reflects the configured failure threshold and detection window.



## 6. Detection Interpretation



Repeated authentication failures may indicate:



- Password guessing

- Brute-force attempts

- Misconfigured services

- Expired credentials

- Legitimate user mistakes



An alert requires further triage, including reviewing the source address, logon type, account, event status codes and related successful logons.



## 7. Known Limitations



- Runs on demand rather than continuously.

- Groups by account only.

- Does not correlate successful authentication after failures.

- Does not automatically suppress duplicate alerts between executions.

- Does not automatically classify legitimate versus malicious failures.

- Cannot establish that an attack succeeded.

- Some Windows logon events do not provide a usable source IP address.

- Current simulation mode provides a fixed positive test scenario.



## 8. Future Engineering Improvements



- Add automated positive and negative regression tests.

- Support account-and-IP correlation.

- Introduce alert deduplication.

- Add event status and logon type enrichment.

- Correlate Event IDs 4625 and 4624.

- Implement continuous monitoring.

- Integrate with a SIEM.



\## 9. SOC Analyst Skills Demonstrated



Windows event analysis, PowerShell scripting, log parsing, behavioural detection, alert generation, security testing and documentation.

