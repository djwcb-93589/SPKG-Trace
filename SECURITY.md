# Security and data privacy

Logs are untrusted input and can contain personal information, credentials, and
adversarial text. The workflow sends selected logs to the configured model service.
Use data that you are authorized to process and an appropriate trusted endpoint.

Credentials belong in environment variables or an untracked `.env.local` file.
Do not embed them in source, URLs, prompts, dataset configurations, examples, or
issue reports. Keep generated results private: they retain original records,
field evidence, local paths, and diagnostic context. Removing a key from the
latest file does not remove it from Git history; rotate any exposed credentials.

Before publishing changes, review the exact staged files and run
`python scripts/check_public_tree.py`. The checker applies boundary and heuristic
checks; it cannot guarantee the absence of arbitrary sensitive information.
Its optional `--secret-env` arguments compare private credential values without
printing them. Do not publish the private configuration files themselves.

Do not include exploit payloads with actual credentials or private logs in public
issues. A project-specific private reporting contact has not yet been designated.
