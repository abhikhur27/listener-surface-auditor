# Listener Surface Auditor

Practical Go CLI for auditing local TCP listeners on Windows, resolving owning processes, and flagging unexpectedly exposed services before they become a networking problem.

## Why this exists

A lot of local tools quietly bind ports: dev servers, database containers, remote desktop helpers, or Windows services you forgot were enabled. This utility turns `netstat` output into a short audit:

- what is listening
- which process owns it
- whether the bind is loopback-only, wildcard, or LAN-exposed
- which listeners deserve a closer firewall / config review

It is a local review tool, not a firewall manager.

The latest version also adds process-level rollups so a machine with many listeners is easier to review by owner instead of by port alone.

## Usage

Basic console audit:

```bash
"C:\Program Files\Go\bin\go.exe" run .\
```

Write shareable artifacts:

```bash
"C:\Program Files\Go\bin\go.exe" run .\ --json-out reports\audit.json --markdown-out reports\audit.md
```

Include TCP aggregate counters too:

```bash
"C:\Program Files\Go\bin\go.exe" run .\ --include-tcp-stats --markdown-out reports\audit.md
```

## Output

- Console summary with exposure breakdown and top-risk listeners
- Process-level rollups showing which executables own the broadest or riskiest listener surface
- Optional JSON report for scripting or archive history
- Optional Markdown brief for a quick manual review pass

## Verification

```bash
"C:\Program Files\Go\bin\go.exe" build .\
"C:\Program Files\Go\bin\go.exe" run .\ --json-out reports\self-check.json --markdown-out reports\self-check.md
```

## Portfolio Positioning

- Project type: Go command-line Windows utility
- Direction fit: practical non-browser local software
- Best demo: audit a dev machine and show which services are exposed beyond loopback
