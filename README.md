# Detecting Behavior *Meaning*: Token Manipulation Hunt
The purpose of this repository is to share a field-tested, working example of detecting Token-manipulation/duplication behavior by correlating identity transitions, process access, and the resulting privileged process.<br> <br>
The detection does not rely on a specific executable name. Instead, it reconstructs the relationship between the process that accessed a privileged token donor, the donor process, and the new SYSTEM process.<br><br>
Repository includes local detection script (PowerShell-based) and Entra detection KQL (for Log Analytics workspace/Microsoft Sentinel hunting view), yet can easily convert the correlation logic to any SIEM/detection platform.

## Why this is important
In order to evolve from basic TTPs to Modern Hunting, we need to understand not only behavior but *meaning* of what we see in the evidence.<br><br>
We Do Not build this hunt around executable names. Or even executables at all. It is Built around relationships and security-context changes, e.g.<br><br>
identity transition<br>
        + process access<br>
        + token-donor relationship<br>
        + privileged child<br>
        + temporal correlation<br><br>
This makes the detection more resilient to different utilities, scripting languages, donor processes, and token-manipulation implementations (Direct Parent-Child, In-Direct Token donor, Direct without Process Acccess, etc.)<br><br>

## Telemetry requirements 
| Telemetry | Purpose |
| --- | --- |
| Sysmon Event ID 1 | Process creation, user, integrity, parent PID/ProcessGuid |
| Sysmon Event ID 10 | ProcessAccess: source process opens target process |
| Security Event ID 4688 | Enrichment for Creator subject, target subject, new process, command line |
| Security Event ID 4703 | Optional enrichment for token privilege changes |

## Detection flow example
Normal user process<br>
        -> Sysmon Event ID 10: ProcessAccess<br>
SYSTEM token donor<br>
        -> duplicated token used for process creation<br>
New process runs as NT AUTHORITY\SYSTEM<br>
        -> Sysmon Event ID 1 + Security Event ID 4688 (enrichment only) + 4703 (Optional enrichment)<br>
Correlation hunt with false-positive suppression using a Local PowerShell script and/or KQL for Microsoft Sentinel/Log Analytics<br>

## Useful References
To get Sysmon, and learn more about Sysmon Configurations, Sentinel & data collection in Entra -
- [Get Sysmon from Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Sysmon Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview)
- [Sysmon Configuration Files](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
- [Azure Monitor — Collect Windows Events with Azure Monitor Agent (AMA)](https://learn.microsoft.com/en-us/azure/azure-monitor/vm/data-collection-windows-events)
- [Microsoft Sentinel — Data Collection Best Practices](https://learn.microsoft.com/en-us/azure/sentinel/best-practices-data)

