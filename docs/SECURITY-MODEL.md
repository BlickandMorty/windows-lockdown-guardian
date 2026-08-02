# Security Model

## What the guardian protects against

- Casual or impulsive edits made from the normal desktop session.
- Accidental loss of browser policies, hosts entries, or installed scripts.
- Drift after Windows or browser updates.
- Removal of one enforcement layer while independent layers remain healthy.
- Corruption of an installed file when a verified canonical copy still exists.

## What it cannot make impossible

A person who retains a local administrator account can eventually take ownership of files, replace scheduled tasks, boot another operating system, or reinstall Windows. A local script cannot make itself mathematically irreversible against the machine owner.

For a stronger boundary, use a standard daily account, keep administrator credentials with a trusted person, use device-management policy, and enforce DNS upstream on a router or managed network. Those controls are outside this repository.

## Why there is no “AI-only” permission

Windows permissions apply to user, group, service, and application identities. An AI agent launched under your account normally has the same Windows token as you; Windows does not know that one process is “the AI.” A SYSTEM task can own and repair files, but invoking an authorized maintenance action still requires a real Windows authorization mechanism.

## Integrity design

The installer creates a canonical baseline, a SHA-256 manifest, and a machine-protected secret used to authenticate that manifest. The guardian validates the manifest before copying a baseline file into place. Installed artifacts are readable to administrators but writable only by SYSTEM during normal operation.

This design prevents a normal user process from silently swapping both a target and its repair copy. It does not defeat a determined administrator or offline disk access.

