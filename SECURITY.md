# Security Policy

EJII interacts with operating-system and network interfaces and includes infrastructure discovery, diagnostics, packet analysis, authentication, and controlled operational functionality. Security reports should describe the affected component and the conditions required to reproduce the issue.

## Reporting a vulnerability

Please do not publish exploitable vulnerability details, credentials, private keys, customer data, or sensitive infrastructure information in a public issue or discussion.

Use GitHub's private vulnerability reporting for this repository when it is available. Otherwise, contact the project owner through [GitHub](https://github.com/EldarJamiyev) and request a private disclosure channel before sending technical details.

Include, where possible:

- The affected version, commit, or branch.
- The affected component and security impact.
- Required permissions, configuration, and preconditions.
- A concise reproduction procedure that does not expose third-party systems or data.
- Relevant logs or test evidence with secrets and sensitive values removed.

Please allow the maintainer reasonable time to investigate and coordinate a fix before public disclosure.

## Security areas in scope

Reports are particularly relevant to:

- Authentication, password handling, sessions, role-based access control, and MFA.
- Network target validation, SSRF protections, scanning boundaries, and probe execution.
- Packet capture, telemetry collection, sensitive-data exposure, and log handling.
- Host automation, remediation authorization, rollback, and command execution boundaries.
- GitHub OAuth integration, API credentials, environment variables, and secret management.
- SQLite persistence, user/session isolation, evidence provenance, and audit-log integrity.
- Dependency, build, deployment, and supply-chain security.

## Safe testing

Only test systems and networks that you own or are explicitly authorized to assess. Do not use EJII to access, scan, capture, modify, or disrupt third-party infrastructure without permission.

Never commit real credentials, access tokens, private keys, customer information, or production telemetry to the repository.
