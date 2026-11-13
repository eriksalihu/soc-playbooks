# Playbook: New SSH authorized key added

- **Detection:** [rules/ssh_authorized_key_added.yml](../rules/ssh_authorized_key_added.yml)
- **ATT&CK:** [T1098.004 Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)

## What the alert means

An `authorized_keys` file in a user's `.ssh` directory on a Linux host was created or changed. Every public key in that file lets the holder of the matching private key log in as that user without a password. An attacker who adds a key keeps access even after the password is changed. Administrators and deployment tools add keys all the time, so the question is whether this key belongs to someone who should have access.

## Triage questions

1. Whose `authorized_keys` file was changed? A change for root or a service account is more serious.
2. Which process and which user made the change? A configuration management agent is expected. A web server process or an interactive shell from an unusual login is not.
3. Which key was added, and does its owner recognise it? Compare the key and its comment with the keys the team knows.
4. How did the user who made the change log in, and from where?
5. Did the alert follow an SSH brute force alert or a suspicious login on the same host?

## Evidence to collect

- The file event: host, file path, time, process and user
- The current content of the file and, if available, the previous version from backup or configuration management
- The fingerprint of each key: `ssh-keygen -lf authorized_keys`
- SSH logins on the host before and after the change (`/var/log/auth.log` or `journalctl -u ssh`, and `last`)
- Shell history of the user who made the change

## Containment

- If the key is not recognised: remove that key from the file (keep a copy as evidence), end the user's active SSH sessions, and reset the user's password.
- Check the `authorized_keys` files of the other accounts on the host, and look for the same key on other hosts.
- If root or a service account is affected, or the change was made by an unexpected process, isolate the host.

## When to escalate

- Nobody recognises the key
- The file belongs to root or a service account
- The change was made by a process that should not write there, such as a web server
- The same unknown key is found on more than one host

## How to close it

- **False positive:** the key owner or the deployment tool is confirmed. Record who owns the key.
- **True positive:** hand over to incident response with the key fingerprint, the login history and the list of hosts where the key was found.
