\# Test Results — Windows Authentication Threat Detection



\## 1. Testing Objective



Validate the detector's ability to identify repeated authentication failures, avoid alerts below the configured threshold and handle live Windows Security log queries.



\## 2. Test Environment



\- Operating system: Windows

\- Scripting environment: PowerShell

\- Log source: Windows Security Event Log

\- Relevant event IDs: 4624 and 4625

\- Simulation method: In-memory PowerShell objects

\- Report format: CSV



Tests were conducted locally in a controlled learning environment.



\## 3. Detection Test Matrix



| ID | Test Scenario | Expected Result | Observed Result | Status |

|---|---|---|---|---|

| T01 | Seven simulated failures within five minutes | Alert | Alert generated | PASS |

| T02 | Three simulated failures within five minutes | No alert | No alert | PASS |

| T03 | Five simulated failures spread over twenty minutes | No alert | No alert | PASS |

| T04 | Failures distributed across three accounts, none reaching threshold | No alert | No alert | PASS |

| T05 | Saved detector executed using TestMode | Alert | Alert generated | PASS |

| T06 | Manual CSV export test | Structured CSV | CSV generated and verified | PASS |

| T07 | Saved detector automatic CSV export | Structured alert CSV | CSV generated and verified | PASS |

| T08 | Upgraded detector Live Mode | Query Security log | NO DATA returned successfully | PASS |



Tests T02–T04 were performed interactively against the detection logic. They have not yet been automated as regression tests in the saved script.



\## 4. Positive Detection Test



\*\*Scenario:\*\* Seven failed authentication events targeting the same simulated account.



\*\*Test account:\*\* `SOC-LAB-USER`



\*\*Simulated source IP:\*\* `192.0.2.10`



\*\*Event ID:\*\* 4625



\*\*Threshold:\*\* Five failures



\*\*Window:\*\* Five minutes



\*\*Observed result:\*\* The detector generated an alert after identifying the first qualifying five-failure window.



The generated CSV contained the alert timestamp, affected account, failure count, source IP, severity, detection rule and data source.



\*\*Outcome: PASS\*\*



\## 5. Negative Detection Tests



\### T02 — Below Threshold



Three failed logons occurred within five minutes.



\*\*Observed:\*\* No alert.



\### T03 — Outside Detection Window



Five failures were distributed over twenty minutes.



\*\*Observed:\*\* No alert.



\### T04 — Multiple Accounts



Failures were distributed across three accounts, with no individual account reaching the configured threshold.



\*\*Observed:\*\* No alert.



These results demonstrate that the tested detection logic considers both event timing and targeted account.



\## 6. Live Mode Validation



The detector was executed against the actual Windows Security log using Event ID 4625.



\*\*Observed output:\*\*



```text

MODE: LIVE - Reading Windows Security log.

Events collected: 0

NO DATA: No matching authentication failures found.

```



\*\*Outcome: PASS — Live log query and empty-result handling.\*\*



No genuine failed-logon events were returned during this test. Consequently, live alert generation against genuine Event ID 4625 records remains untested.



\## 7. CSV Reporting Validation



The saved detector was executed in Simulation Mode.



\*\*Observed:\*\*



\- Simulated events collected: 7

\- Detection alert generated: Yes

\- CSV automatically exported: Yes

\- Structured alert fields verified: Yes

\- DataSource: SIMULATION



\*\*Outcome: PASS\*\*



\## 8. Security and Safety



The simulated authentication events existed only in PowerShell memory.



The tests did not require:



\- Password guessing against real accounts

\- Account lockouts

\- Modification of Windows Security event records

\- External network attacks



The documentation IP address `192.0.2.10` was used for simulation.



\## 9. Overall Assessment



The prototype successfully demonstrated:



\- Configurable threshold-based detection

\- Sliding-window analysis

\- Account-level correlation

\- Positive and negative test scenarios

\- Live Windows Security log querying

\- Automatic CSV alert reporting



The project is suitable for demonstrating foundational SOC detection engineering skills.



It is not yet a production-ready intrusion detection system.



\## 10. Remaining Validation Work



\- Automate the negative test cases against the saved detector.

\- Validate parsing of genuine Event ID 4625 records.

\- Test multiple source IP addresses.

\- Test repeated executions and duplicate alert handling.

\- Validate behaviour when Security log access is denied.

