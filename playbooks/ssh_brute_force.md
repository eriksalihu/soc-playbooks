# Playbook: SSH brute force on a Linux server

- **Detection:** [rules/ssh_brute_force.yml](../rules/ssh_brute_force.yml)
- **ATT&CK:** [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Helper tool:** [log-sentinel](https://github.com/eriksalihu/log-sentinel) finds the same pattern in a copy of `auth.log` and also reports a success after failures.

## What the alert means

One source IP produced ten or more failed SSH password logins on a server within five minutes. Someone, almost always an automated tool, is guessing passwords. For a server that is reachable from the internet this happens every day and is usually harmless. The alert matters when a guess succeeds, when the source is internal, or when the targeted accounts are real.

## Triage questions

1. Did any login from this source IP succeed, during or after the failures?
2. Is the source external or internal? An internal source means a host inside the network may be compromised.
3. Which usernames were tried? Generic names (root, admin, test) point to a random scan. Real employee names point to a targeted attack.
4. Is the server supposed to accept SSH from that network at all?
5. Is the source a known system, such as a monitoring tool or a job with an outdated password?

## Evidence to collect

- The sshd log lines for the source IP: `/var/log/auth.log` on Debian and Ubuntu, `/var/log/secure` on Red Hat based systems, or `journalctl -u ssh`
- Time of the first and last attempt, number of attempts, list of usernames tried
- Any `Accepted password` or `Accepted publickey` line from the same source
- If a login succeeded: the output of `last` for that user, the user's shell history, and any new files in `~/.ssh/`

## Containment

- No successful login: block the source IP at the firewall or let a tool such as fail2ban do it. No further action is needed on the host.
- Successful login that the account owner does not recognise: treat the account as compromised. Lock the account, end its sessions, reset the password, and check `authorized_keys` for keys the owner did not add (see the [authorized key playbook](ssh_authorized_key_added.md)).

## When to escalate

- Any successful login from the attacking source
- The source is an internal host
- The targeted accounts are real, privileged or service accounts
- The same source is attacking many servers at once

## How to close it

- **False positive:** a known system or user caused the failures. Record which one and ask its owner to fix the stored password.
- **True positive, no impact:** external guessing with no successful login. Record the source IP and the block, then close.
- **True positive, with impact:** a login succeeded. Hand over to incident response with the evidence above and keep the ticket open until the account is secured.
