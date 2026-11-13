# How soc-playbooks works

This document explains the repository in plain language: what a Sigma rule is made of, how each of the five rules works and where it can be wrong, how the playbooks are built, and what CI checks.

## What a Sigma rule is

Sigma is a vendor-neutral format for writing detections as YAML files. A rule describes *what to look for in which logs*, and a converter (`sigma convert`) turns it into the query language of a specific SIEM. Writing a rule once in Sigma means it is not tied to one product.

Every rule in `rules/` has the same parts:

| Field | Meaning |
|---|---|
| `title` | Short name of what is detected. |
| `id` | A random UUID that identifies the rule for ever, even if the title changes. |
| `status` | How mature the rule is. All rules here are `experimental`: validated, but not tuned in a real environment. |
| `description` | What the rule detects and why it matters. |
| `references` | Where to read more. Here, the ATT&CK technique page. |
| `tags` | The ATT&CK tactic and technique, for example `attack.persistence` and `attack.t1098.004`. |
| `logsource` | Which logs the rule applies to, by `product`, `service` or `category`. |
| `detection` | Named groups of conditions (selections) and a `condition` line that combines them. |
| `falsepositives` | Known harmless causes. |
| `level` | How serious a match is: low, medium, high or critical. |

Inside `detection`, a selection is a list of `field: value` pairs that must all match. A list of values means "any of these". Modifiers after a `|` change how the value is compared: `endswith` and `contains` are the two used here. String comparison in Sigma is case-insensitive.

## The rules

### 1. ssh_brute_force.yml (T1110, medium)

This file contains two documents separated by `---`.

- The **base rule** matches a single sshd log line containing `Failed password for`. Its level is low, because one failed login means nothing.
- The **correlation rule** refers to the base rule by its `name` and counts its matches: `type: event_count`, grouped by `src_ip`, within a `timespan` of 5 minutes, with the condition `gte: 10` (ten or more).

- **Why ten in five minutes:** a person who has forgotten a password gives up or gets it right after a few tries. Ten failures in five minutes from one address is a tool. The number is higher than the default of 5 in log-sentinel because a SIEM rule runs all the time on every server, and a low threshold there would bury the analyst in alerts.
- **Likely false positives:** a script with an outdated password; many users behind one NAT address; an authorised password audit.
- **Can miss:** slow guessing that stays under the threshold, guessing from many addresses, and attempts with SSH keys, which do not log `Failed password`.

### 3. encoded_powershell.yml (T1059.001, medium)

- **Log source:** `category: process_creation`, `product: windows`. This is the generic Sigma name for "a process was started", which covers Security event 4688 and Sysmon event 1.
- **Logic:** two selections that must both match. `selection_image`: the program path ends with `\powershell.exe` or `\pwsh.exe`. `selection_parameter`: the command line contains ` -EncodedCommand `, ` -enc `, ` -ec ` or ` -e `.
- **Why the short forms:** PowerShell accepts any unambiguous beginning of a parameter name, so attackers rarely write the full word. The spaces around each form keep the rule from matching other text that merely contains those letters.
- **Why it matters:** the parameter takes the command as Base64, so the real command is not readable in the log without decoding it.
- **Likely false positives:** software deployment and management tools, and administrator scripts, which encode commands to avoid quoting problems. In a real environment this rule needs a filter for the known parent processes.
- **Can miss:** other ways of hiding a command (string concatenation, reading the script from a file or the registry), other unambiguous abbreviations such as `-enco`, and PowerShell started under a renamed executable.

### 4. new_local_admin.yml (T1136.001, high)

- **Log source:** Windows Security log.
- **Logic:** `EventID: 4732` (a member was added to a security-enabled local group) and `TargetSid: S-1-5-32-544`. That SID is the built-in Administrators group. It is the same on every Windows system and in every language, which is why the rule uses the SID and not the group name.
- **Why this event:** creating a local account (event 4720) is not dangerous in itself. The step that gives it power is adding it to Administrators, so that is where the rule alerts. The playbook then looks back for the 4720 event.
- **Likely false positives:** IT staff setting up a machine or granting temporary rights; installers that create a service account.
- **Can miss:** an attacker who uses an existing administrator account and never creates a new one, and changes to domain groups, which produce different events.

### 5. event_log_cleared.yml (T1685.005, high)

- **About the technique ID:** this technique used to be T1070.001 (Indicator Removal: Clear Windows Event Logs). In the current version of ATT&CK it is T1685.005 (Disable or Modify Tools: Clear Windows Event Logs) under the Defense Impairment tactic, and the old ID redirects to the new one. Older rules and reports still use T1070.001, so it is worth knowing both.

- **Log source:** Windows Security log.
- **Logic:** `EventID: 1102`, the event Windows writes when the Security log is cleared.
- **Why high:** there are very few normal reasons to clear the Security log, and it destroys evidence. There is no threshold: one event is enough.
- **Likely false positives:** an administrator resetting a test machine or rebuilding a host.
- **Can miss:** clearing of other logs (recorded as event 104 in the System log), deleting single events with special tools, or stopping the logging service. It also only works if events are forwarded off the host, because the alert has to leave the machine before the attacker can interfere.

### 6. ssh_authorized_key_added.yml (T1098.004, medium)

- **Log source:** `category: file_event`, `product: linux`: file creation and change events from a tool such as auditd or Sysmon for Linux.
- **Logic:** `TargetFilename` ends with `/.ssh/authorized_keys` or `/.ssh/authorized_keys2`. Matching the end of the path covers every user's home directory, including `/root`.
- **Why it matters:** a key in that file is a password-free login that survives a password change.
- **Likely false positives:** users and administrators adding their own keys; configuration management and cloud provisioning tools. In a real environment those tools are filtered by process name.
- **Can miss:** servers configured to read keys from a different location (`AuthorizedKeysFile` in `sshd_config`), and hosts without file monitoring.

### Scenario 2 has no rule

"Phishing email reported by a user" starts with a person, not a log event, so it has a playbook only.

## The playbooks

Each file in `playbooks/` has the same six sections, in the order an analyst needs them:

1. **What the alert means:** what happened, and why it may or may not be a problem.
2. **Triage questions:** the questions whose answers separate a false positive from a real incident.
3. **Evidence to collect:** the exact logs and artefacts, with event IDs and file paths.
4. **Containment:** the first actions that stop further damage without destroying evidence.
5. **When to escalate:** the conditions under which tier 1 hands over.
6. **How to close it:** what to record for a false positive and for a true positive.

Two ideas repeat through all of them: answer "did it succeed?" before anything else, and never destroy evidence while containing (disable an account before deleting it, isolate a host without powering it off).

## What CI checks

`.github/workflows/ci.yml` runs on every push and pull request:

1. Installs `sigma-cli`.
2. Runs `sigma check --fail-on-issues rules/`. This parses every rule and runs the Sigma validators, which catch problems such as a missing or duplicate id, a condition that refers to a selection that does not exist, an invalid ATT&CK tag, or wildcards where a modifier should be used. `--fail-on-issues` makes the build fail on validation issues as well as on parse errors.
3. Confirms that every file in `rules/` has a playbook with the same name.
4. Writes the output of `sigma check` to the job summary.

A green build means the rules are valid Sigma. It does not mean they have been tested against real attack data, which is why they stay `experimental`.
