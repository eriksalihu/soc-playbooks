# Playbook: New local administrator account

- **Detection:** [rules/new_local_admin.yml](../rules/new_local_admin.yml)
- **ATT&CK:** [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)

## What the alert means

An account was added to the local Administrators group on a Windows host (Security event 4732). Attackers who have gained control of a machine often create a local account and make it an administrator, so that they can come back even if the password of the account they first used is changed. IT staff do the same thing for normal reasons, so the question is who did it and whether there is a request behind it.

## Triage questions

1. Who made the change? The event names the account that performed it.
2. Which account was added, and when was it created? Look for event 4720 (account created) on the same host shortly before.
3. Is there a ticket or change request that explains it?
4. Was the change made during working hours, from the usual admin workstation?
5. Has the new account been used to log on since then?

## Evidence to collect

- The 4732 event: host, time, who made the change, which account was added
- Event 4720 for the creation of the account, if it is new
- Logon events (4624) for the account that made the change and for the new account
- Process creation events from the same time, for example `net user` or `net localgroup` commands
- The current members of the local Administrators group

## Containment

- If nobody can explain the change: disable the new account (do not delete it yet, it is evidence), and treat the account that made the change as compromised: reset its password and end its sessions.
- If the host shows other signs of compromise, isolate it from the network.

## When to escalate

- No ticket or owner can be found for the change
- The account that made the change does not normally administer this host
- The host is a server, a domain controller or holds sensitive data
- The new account name imitates a system or service account

## How to close it

- **False positive:** confirmed by the IT team with a ticket reference. Record the reference.
- **True positive:** hand over to incident response with the events above. The new account stays disabled until the investigation is finished.
