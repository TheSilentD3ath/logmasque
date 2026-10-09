# Security policy

## Supported versions

Security fixes are made for the latest release only.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.

Include a description, the affected version and steps to reproduce with synthetic data. Never attach real logs, mapping stores, `.anonstore` files or mapping CSV files.

You can expect an acknowledgement within a few days. Fixes are released as soon as practical and credited in the changelog unless you prefer otherwise.

## Scope

Examples of issues in scope:

- Sensitive values that pass through masking although the documentation says they are detected.
- Ways to read or restore mapping-store contents without the Windows account or the store password.
- A store or backup that gets overwritten, lost or written without protection.
- Requests to the local interface that are accepted from another origin, another host name or without the session token.
- Masked output or logs that contain original values in unexpected places.

Out of scope:

- Values the documentation lists as not detected (see "Limitations" in the README).
- Re-identification through context in masked text. Reversible pseudonymization does not guarantee anonymity.
- Attacks that require control of the user account that owns the store.

## Handling sensitive data

- The mapping store, its backups (`mapping.json.bak-*`), `.anonstore` exports, `--mapping-csv` output and the output of `logmasque store rows` can reverse the masking. Keep them private and out of version control.
- The collection manifest and `logmasque.log` contain local paths.
- Always review masked output before sharing it.
