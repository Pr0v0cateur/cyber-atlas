# Security Policy

## Supported Version

This repository currently supports the `main` branch.

## Secret Handling

Never commit real credentials, API keys, tokens, passwords, private keys, or
database dumps. Use the provided example environment files as templates:

- `.env.example`
- `.env.production.example`

Local environment files are ignored by Git:

- `.env`
- `.env.production`
- `.env.*`

If a secret is accidentally committed, treat it as compromised immediately:

1. Revoke or rotate the exposed credential at the provider.
2. Remove it from the repository.
3. Rewrite Git history before pushing if the commit has not yet been published.
4. If it was already pushed, keep the secret rotated even if history is cleaned.

## Local Checks

Run the repository secret scan before pushing:

```bash
python scripts/secret_scan.py
```

Optional pre-commit setup:

```bash
pip install pre-commit
pre-commit install
```

## Deployment Guidance

- Use unique secrets per environment.
- Do not reuse development credentials in production.
- Keep the GitHub repository private unless a public submission is required.
- Restrict repository access to trusted collaborators only.
- Enable GitHub secret scanning and Dependabot alerts when the repository is
  created.
- Rotate local `.env` credentials before any public demonstration if they were
  shared on screen or sent to anyone else.

## Reporting Security Issues

For thesis or academic review use, report issues directly to the project author
or supervisor through the agreed private communication channel. Do not disclose
security issues publicly before they have been reviewed.
