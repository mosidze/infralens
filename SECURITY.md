# Security

InfraLens is run by people who give it access to an AWS account, so how it
behaves matters more than most tools. This is what it does, and what it does
not.

## What it does

- **Read-only, enforced in code.** Every AWS SDK call passes a guard that
  refuses any operation not named `Describe*`, `List*` or `Get*` (the only
  exceptions are the SDK's own token refresh and role assumption). A bug
  cannot change an account. `--api-log FILE` records every call.
- **Minimal permissions.** `infralens policy` prints the exact IAM actions the
  selected checks need. `infralens doctor` tells you which checks will work
  with the credentials at hand, before an engagement.
- **Local only.** Nothing is sent anywhere unless you configure a language
  model *and* agree to a shown payload. A model on loopback (Ollama) is not
  asked. The payload is findings and totals with names, account numbers, ARNs
  and e-mail shapes removed.
- **Terraform state is treated as a secret.** It is read only when you name
  it (`--tfstate`); an allow-list of attributes is kept and everything else is
  dropped in memory. Tests plant secrets in a state file and prove they never
  reach a scan, a report or a prompt.
- **The web app (`infralens serve`)** listens on loopback only and refuses
  other addresses. It needs a token (kept in `~/.infralens/serve.token`, mode
  0600, exchanged for a `SameSite=Strict` cookie), checks `Host` against
  DNS-rebinding, requires a same-origin `Origin` and a custom header on
  writes, and serves pages under a strict CSP. The report page has no network
  access at all.
- **Secrets at rest.** API keys live in `~/.infralens/secrets.json` (0600) or
  in an environment variable; settings only hold a reference. Scans, history
  and audit packs are written 0600/0700 because they inventory an account.

## What it does not do

- It does not enable AWS services on your behalf, and it does not write to
  your account. Cleanup scripts are text; they print what they would do by
  default and need explicit flags to change anything.
- It is not a CSPM or a compliance product. Its security checks are a thin
  layer plus ingestion of what Security Hub, Trusted Advisor and Prowler
  already found.
- It does not know your plans. Findings are evidence and conditional
  suggestions, not verdicts.

## Reporting a problem

Please report vulnerabilities privately through GitHub's *Report a
vulnerability* (Security tab) rather than a public issue. Include the version
(`infralens version`) and, if you can, how to reproduce it. Anything that lets
the tool perform a write operation, leak a secret, or be driven from another
origin is treated as serious.
