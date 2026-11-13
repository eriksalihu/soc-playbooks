# Playbook: Encoded PowerShell command

- **Detection:** [rules/encoded_powershell.yml](../rules/encoded_powershell.yml)
- **ATT&CK:** [T1059.001 Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

## What the alert means

PowerShell was started with the `-EncodedCommand` parameter or one of its short forms. The parameter takes the command as a Base64 string. Management tools use it for convenience, and attackers use it to hide the command from people and from simple filters. The encoding itself proves nothing. What matters is what the decoded command does and what started it.

## Triage questions

1. What does the command say once it is decoded? The value is Base64 of UTF-16LE text.
2. Which process started PowerShell? A management agent is expected. Word, Excel, Outlook, a browser or a script host is not.
3. Which user ran it, and is that normal for this user and this host?
4. Does the decoded command download something, contact an address, switch off a security tool, or start another encoded stage?
5. Has the same command been seen on other hosts? The same command on hundreds of hosts at a planned time is usually software deployment.

## Evidence to collect

- The full command line, the parent process and the user, from the process creation event (Security event 4688 or Sysmon event 1)
- The decoded command
- PowerShell script block logs (event 4104) from the same time, if enabled
- Network connections of the PowerShell process, and files it created
- Process activity on the host for the minutes before and after

Decode the command in an analysis tool, never by running it.

## Containment

- If the decoded command is malicious or cannot be explained: isolate the host from the network, keep it powered on so that memory evidence is not lost, and block any addresses or domains found in the command.
- If the user's account is involved: reset the password and end the sessions.

## When to escalate

- The decoded command downloads or runs code from the internet
- The parent process is an Office application, a browser or a script host
- The command disables logging or security software
- The same unexplained command appears on more than one host

## How to close it

- **False positive:** a known management or deployment tool. Record the tool and the parent process, and propose a filter for that parent so the rule stays useful.
- **True positive:** hand over to incident response with the decoded command, the parent process chain and the list of affected hosts.
