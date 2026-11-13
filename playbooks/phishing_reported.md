# Playbook: Phishing email reported by a user

- **Detection:** none. This alert comes from a person, through a report button or a forwarded email, so there is no Sigma rule.
- **ATT&CK:** [T1566 Phishing](https://attack.mitre.org/techniques/T1566/)
- **Helper tool:** [phish-triage](https://github.com/eriksalihu/phish-triage) scores the saved `.eml` file offline and prints defanged indicators for the ticket.

## What the alert means

A user thinks an email is suspicious and reported it. Most reports turn out to be spam or legitimate marketing, but each one has to be checked, because a real phishing email was probably sent to other people too and some of them may have clicked.

## Triage questions

1. Did the user only read the email, or did they click a link, open an attachment, or enter a password?
2. Who is the real sender? Compare the From address, the Reply-To address and the Return-Path.
3. Did SPF, DKIM and DMARC pass according to the `Authentication-Results` header?
4. Where do the links really go? Compare the visible text with the target.
5. Is there an attachment, and what type is it really?
6. Who else received the same email?

## Evidence to collect

- The original email as a `.eml` file, with full headers. A forwarded copy loses the original headers.
- Sender address, Reply-To, Return-Path, subject, time received
- All URLs and domains, defanged, and the SHA-256 hash of each attachment
- The list of recipients, from a message trace in the mail system
- If the user clicked: proxy or DNS logs for the domain, and the time of the click
- If the user entered a password: sign-in logs for that account after that time

Never open the links or the attachment on a normal workstation. Use an isolated analysis environment if a closer look is needed.

## Containment

- Remove the email from all mailboxes that received it.
- Block the sender address, the sending domain and the URLs at the mail gateway and the web proxy.
- If a password was entered: reset it immediately, end all active sessions, and review the account's recent sign-ins, mail forwarding rules and MFA devices.
- If an attachment was opened: isolate the workstation and hand it to incident response.

## When to escalate

- A user entered credentials or opened the attachment
- The email was aimed at specific people, such as finance staff or executives
- Many recipients received it, or it came from a compromised internal mailbox
- The email asks for a payment or a change of bank details

## How to close it

- **False positive:** legitimate email or ordinary spam. Tell the user and thank them for reporting.
- **True positive, no impact:** phishing, nobody clicked. Record the indicators and the blocks, confirm the email was removed, and tell the user.
- **True positive, with impact:** someone clicked or entered data. Hand over to incident response and keep the ticket open until the accounts and hosts involved are secured.
