# Security policy

ProxyMind handles sensitive client traffic and holds a CA key that can intercept TLS. Security bugs in ProxyMind itself are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and the impact you expect. You'll get an acknowledgement within 5 working days.

## In scope

- Leaks of the CA private key or project data
- Ways for an agent, plugin or target response to bypass scope or rules-of-engagement enforcement
- Remote access to the local API without the token
- Memory-safety or parser bugs triggered by hostile traffic

## Out of scope

- Vulnerabilities in targets you tested *with* ProxyMind
- Issues that need an attacker who already controls your machine
