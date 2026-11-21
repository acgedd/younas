# YourNAS — Claude Code project instructions

Self-hosted private file server for one owner and a few trusted friends. Windows host, Python/FastAPI backend, local NTFS storage, Tailscale remote access, web/iOS clients. Read `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/API.md`, `docs/ROADMAP.md` before working. Keep it small, simple, and secure; this is not an enterprise platform.

## Working rules (all agents and the main session)

- Inspect the repository and machine before assuming. Do not invent requirements.
- One phase at a time. Do not implement future phases. Do not silently change architecture; report flaws instead.
- Never weaken security to make a test pass. Never expose SMB 445 or any new service publicly. Never disable the firewall. No plaintext passwords, hardcoded secrets, or secrets in logs or git.
- Run existing tests before and after changes. Small reversible changes. Commit at each phase checkpoint. No force push, destructive reset, or history rewrite unless explicitly instructed.
- Keep facts, requirements, recommendations, assumptions, and unresolved risks distinct in reports.

## Subagents (in `.claude/agents/`)

| Agent | Mode | Owns / does |
|---|---|---|
| yournas-architect | read-only | architecture, phase boundaries, API/auth design reviews |
| yournas-backend | edits | routes, services, auth/authz middleware, DB, config, backend tests |
| yournas-security | read-only | threat model, security review of auth, paths, uploads, network |
| yournas-storage | edits | storage package: path resolution, file ops, uploads, tests for them |
| yournas-network | inspect, gated changes | Tailscale, firewall, ports, binding, startup |
| yournas-ios | edits (cannot build on Windows) | SwiftUI client |
| yournas-qa | edits tests only | negative, security, regression, failure-mode tests |
| yournas-reviewer | read-only | independent diff review with severities |
| yournas-docs | edits docs only | README and docs/ matching real behavior |
| yournas-ops | edits scripts/ops docs | restart, config, logs, health, backup/recovery docs |

Subagents cannot launch other subagents. The main session delegates, passes only the relevant PRD/doc excerpts, files, and task, and merges results.

## Invocation map

- Phase 0 / architecture review: architect, security, network, ops (read-only, may run in parallel).
- Backend feature: backend (+ storage if filesystem behavior, + security if sensitive) -> qa -> reviewer.
- Authentication change: backend + security -> qa -> reviewer.
- Authorization change: backend + security + storage -> qa -> reviewer.
- Filesystem change: storage + security -> qa.
- Network/Tailscale/firewall: network + security -> qa.
- API contract change: backend, ios if it depends on it, qa.
- iOS work: ios (+ backend if API changes) -> qa -> reviewer.
- Major architecture change: architect + security BEFORE implementation.
- Release: security, reviewer, qa, ops, docs.
- Important phase pipeline: architect -> implementer -> qa -> security -> reviewer -> docs -> commit. Small changes: implement -> tests -> review if needed -> commit.

## Automatic escalation

Auth change -> security, qa. Authorization change -> security, storage, qa. Filesystem change -> storage, security. Firewall/network change -> network, security. API change -> backend, ios (if affected), qa. Architecture change -> architect, security. Release -> reviewer, security, qa, ops, docs.

## Parallelism and ownership

Parallelize only independent, mostly read-only work. Never run two agents that edit the same files or redesign the same subsystem. One implementation owner per subsystem: backend code -> yournas-backend; filesystem -> yournas-storage; networking -> yournas-network; iOS -> yournas-ios; docs -> yournas-docs; tests -> yournas-qa.

## Disagreements

Do not average opinions. Identify the requirement, facts, security impact, and assumptions. Escalate significant disagreements to yournas-architect (and yournas-security if security-related), then report the decision and reasoning. Review agents must challenge the implementation; "no issues found" is acceptable only when true.

## Needs explicit user confirmation first

Deleting user data, changing the storage root, formatting disks, migrating storage, changing critical firewall rules, exposing a new public service, changing authentication policy, disabling a security control, destructive database migrations. Prepare and explain; do not execute blindly.
