# Playbook: Windows event log cleared

- **Detection:** [rules/event_log_cleared.yml](../rules/event_log_cleared.yml)
- **ATT&CK:** [T1685.005 Disable or Modify Tools: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) (formerly T1070.001; the old ID now redirects to this one)

## What the alert means

The Security event log on a Windows host was cleared (Security event 1102). Windows writes this event as the first entry of the new, empty log, and it names the account that did it. Clearing the Security log is rare in normal operation, and attackers do it to remove the record of what they did. The local evidence is now gone, so the investigation depends on copies of the events that were forwarded elsewhere before the log was cleared.

## Triage questions

1. Which account cleared the log, and from which logon session?
2. Is there a ticket that explains it, such as a rebuild or a test machine being reset?
3. What happened on the host in the hours before the log was cleared, according to the SIEM and the endpoint security tool?
4. Were other logs cleared as well? Event 104 in the System log records the clearing of other logs.
5. Is the same account active on other hosts?

## Evidence to collect

- The 1102 event: host, time and account
- Events from this host that were already forwarded to the SIEM, especially logons (4624), new accounts (4720), group changes (4732) and process creation (4688)
- Endpoint security alerts and process history for the host
- Logon events for the same account on other hosts

## Containment

- If the clearing cannot be explained: isolate the host, keep it powered on, and reset the password of the account that cleared the log.
- Do not reboot or clean the host. What is left in memory and on disk is needed for the investigation.

## When to escalate

- Always, unless an administrator confirms the action and a ticket exists. An unexplained cleared Security log is treated as a sign of compromise.
- Immediately if the host is a server or domain controller, or if the account is a privileged one

## How to close it

- **False positive:** confirmed by the administrator who did it, with a ticket reference.
- **True positive:** hand over to incident response with the timeline rebuilt from the forwarded events.
