# Windows Lockdown Guardian

A layered, self-repairing Windows restriction toolkit for people who want deliberate friction around explicitly named websites and applications while preserving ordinary work, school, gaming, accessibility, Microsoft, and official Qobuz use.

The project was rebuilt from a production Windows setup that combined local DNS/hosts enforcement, Chrome and Edge enterprise policies, application-name restrictions, SYSTEM scheduled tasks, canonical repair copies, integrity manifests, and continuous verification.

## Safety model

This is consequential system-hardening software. Read [the security model](docs/SECURITY-MODEL.md) and [the operational warning](docs/WARNING.md) before applying it.

- The default command is audit-only.
- Applying requires elevation and an exact acknowledgement phrase.
- The example policy is intentionally narrow: YouTube, X/Twitter, and a starter set of music-streaming services other than official Qobuz. `adultDomains` starts empty because a short static list cannot honestly represent the whole adult-content category; populate exact domains and use a reputable DNS category filter for broad coverage.
- No uninstall, bypass, temporary-exception, or weakening command is shipped for permanent policies.
- A Windows administrator can ultimately replace the OS or take ownership. This project increases friction and self-repairs drift; it does not claim mathematical irreversibility.
- NextDNS is optional. Local hosts and browser-policy layers work without a paid service, though DNS filtering across every app/device requires a DNS provider or managed network.

## Quick start

1. Copy `config/policy.example.json` to `config/policy.json`.
2. Review every domain and executable name.
3. Run the audit:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Install-Lockdown.ps1 -ConfigPath .\config\policy.json
```

4. Review the report in `reports`.
5. Apply only after you understand the consequences:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Install-Lockdown.ps1 `
  -ConfigPath .\config\policy.json `
  -Apply `
  -Acknowledgement 'I UNDERSTAND THIS IS A PERMANENT RESTRICTION'
```

6. Verify:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\Verify-Lockdown.ps1
```

## Layers

| Layer | Role |
|---|---|
| Hosts fallback | Blocks named domains locally even if the optional DNS client is absent. |
| Chrome/Edge policy | Blocks URLs inside managed Chromium browsers. |
| Application restrictions | Blocks explicitly named streaming/social clients without disabling unrelated software. |
| SYSTEM guardian | Reapplies the policy at startup and hourly and repairs protected source files from a canonical baseline. |
| Integrity manifest | Detects drift in installed policy, scripts, and rule documents. |
| Optional DNS export | Produces a plain denylist for manual import into NextDNS or another provider; no account key is stored. |

## Compatibility principles

The installer never applies broad category names such as “social,” “media,” or “entertainment” to local browser policies. Exact named gates are safer for school and developer workflows. `allowDomains` is checked for collisions before anything is applied, and Qobuz is a mandatory allow invariant in the example policy.

## License

MIT. Windows, Edge, Chrome, NextDNS, Qobuz, and other marks belong to their respective owners.
