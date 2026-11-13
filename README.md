# soc-playbooks

Six alerts a tier-1 SOC analyst meets, each with an original Sigma detection rule and a step-by-step response playbook.

[![CI](https://github.com/eriksalihu/soc-playbooks/actions/workflows/ci.yml/badge.svg)](https://github.com/eriksalihu/soc-playbooks/actions/workflows/ci.yml)

## Why a SOC analyst would use it

A detection without a response plan produces alerts that nobody knows how to handle, and a response plan without a detection never gets used. This repository keeps the two together. Each scenario has a rule that says exactly what fires the alert, and a playbook that says what the alert means, what to ask, what to collect, how to contain it, when to escalate and how to close it.

## Features

- Five original Sigma rule files in `rules/`, written in the vendor-neutral Sigma format so they can be converted to the query language of most SIEMs
- Six playbooks in `playbooks/`, all with the same six sections so they are quick to scan during triage
- Every rule has an id, status, description, log source, detection logic, false positives, level and MITRE ATT&CK tags
- CI validates every rule with `sigma check` and confirms that every rule has a playbook

## Coverage

| # | Scenario | Rule | Playbook | ATT&CK technique |
|---|---|---|---|---|
| 1 | SSH brute force on a Linux server | [ssh_brute_force.yml](rules/ssh_brute_force.yml) | [ssh_brute_force.md](playbooks/ssh_brute_force.md) | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force |
| 2 | Phishing email reported by a user | none (reported by a person) | [phishing_reported.md](playbooks/phishing_reported.md) | [T1566](https://attack.mitre.org/techniques/T1566/) Phishing |
| 3 | Encoded PowerShell command | [encoded_powershell.yml](rules/encoded_powershell.yml) | [encoded_powershell.md](playbooks/encoded_powershell.md) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell |
| 4 | New local administrator account | [new_local_admin.yml](rules/new_local_admin.yml) | [new_local_admin.md](playbooks/new_local_admin.md) | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account |
| 5 | Windows event log cleared | [event_log_cleared.yml](rules/event_log_cleared.yml) | [event_log_cleared.md](playbooks/event_log_cleared.md) | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Disable or Modify Tools: Clear Windows Event Logs (formerly T1070.001) |
| 6 | New SSH authorized key added | [ssh_authorized_key_added.yml](rules/ssh_authorized_key_added.yml) | [ssh_authorized_key_added.md](playbooks/ssh_authorized_key_added.md) | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) Account Manipulation: SSH Authorized Keys |

Two scenarios have a companion tool for the hands-on part of the triage:

- Scenario 1: [log-sentinel](https://github.com/eriksalihu/log-sentinel) finds SSH brute force and a login success after failures in a copy of `auth.log`.
- Scenario 2: [phish-triage](https://github.com/eriksalihu/phish-triage) scores a reported `.eml` file offline and lists defanged indicators.

## Quick start

Read a playbook directly on GitHub, or validate the rules locally:

```bash
git clone https://github.com/eriksalihu/soc-playbooks.git
cd soc-playbooks
python -m pip install sigma-cli
sigma check --fail-on-issues rules/
```

To use a rule in a SIEM, convert it with `sigma convert` and the backend plugin for that product. The field names in the rules follow the Sigma conventions, so the conversion also needs the processing pipeline that maps them to the field names of your log source.

## How each detection works

| Rule | Log source | Fires when |
|---|---|---|
| ssh_brute_force | Linux sshd log | One source IP causes 10 or more `Failed password` events within 5 minutes. The file holds a base rule for the single event and a Sigma correlation rule that counts them. |
| encoded_powershell | Windows process creation | `powershell.exe` or `pwsh.exe` starts with `-EncodedCommand` or a short form (`-enc`, `-ec`, `-e`). |
| new_local_admin | Windows Security log | Event 4732: a member is added to the local Administrators group (SID S-1-5-32-544). |
| event_log_cleared | Windows Security log | Event 1102: the Security log was cleared. |
| ssh_authorized_key_added | Linux file events | A file ending in `/.ssh/authorized_keys` or `/.ssh/authorized_keys2` is created or changed. |

The reasoning behind each rule, its threshold and its likely false positives is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Limitations

- The rules are validated for syntax and Sigma best practice by `sigma check`. They have not been run against a production SIEM, so they are marked `experimental` and need tuning for a real environment.
- Each rule depends on its log source being collected: process creation logging with command lines on Windows, file event monitoring on Linux, and so on.
- The SSH correlation rule needs a SIEM backend that supports Sigma correlations and a parsed `src_ip` field.
- The rules are deliberately simple and can be evaded, for example by PowerShell obfuscation that avoids the `-EncodedCommand` parameter.
- The playbooks are general. Real playbooks name the specific tools, teams and contact paths of one organisation.

## Next steps

- Add sample log events for each rule and test the rules against them
- Add filters for the most common false positives, such as known management tools
- Add scenarios: suspicious scheduled task, impossible-travel sign-in, malware alert from endpoint protection
- Add converted example queries for one SIEM

## License

[MIT](LICENSE)
