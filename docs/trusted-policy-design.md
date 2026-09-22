# Trusted policy design for the Linux MVP

## Decision

The persistent lock registry must live outside the AI process's authority. A file owned and writable by the same Unix user as the agent is insufficient: an agent with a filesystem grant to that location could edit or replace it, then ask for a new domain. Requiring a password in an ordinary CLI does not solve this if the agent can invoke that CLI or reuse the authenticated channel.

The first implementation uses a small privileged service and a root-owned policy store. The service owns policy mutations and accepts only root peers on a local Unix socket. For now, administrators invoke the client with `sudo`; the agent domain uses `no_new_privs`, so it cannot become root with a setuid helper. This is a prototype authorization boundary, not yet a polished user-presence flow. The service must never treat an approval inside an AI application as unlock authorization.

## Control path

1. User requests a lock or unlock in an AIShield UI or CLI.
2. The service authenticates the request through the operating system and confirms it came from a trusted interactive session outside an AI domain.
3. The service validates the target's filesystem identity and writes the policy atomically in a directory agents cannot modify.
4. The service records the policy revision and checks running domains affected by the change.
5. A newly added lock is reported as enforced only after affected domains exit or are restarted under the new revision. Unlocking also requires a new domain for access to expand.

The service's root-peer check is implemented and tested. Interactive authorization for non-root users, caller classification across external helpers, and safe handling of already-running agents remain **unresolved security gates**. The current `unlock` command is for a root administrator only; it must not be advertised as the finished product flow.

## Data and process boundaries

- Policy storage: root-owned directory and files, no agent write access, atomic replacement, durable revision metadata, and rollback detection.
- Privileged parser: narrow schema and bounded input; no shell invocation or network-facing endpoint.
- Agent launcher: opens a policy snapshot through the trusted service, validates grants against locks, closes inherited descriptors, and installs Landlock before `exec`.
- Session tracking: records domain process identity and policy revision. It must distinguish a running domain from an exited PID that has been reused.
- Audit: metadata-only deny events; logging failure must not disable enforcement.

## Required attack tests

- Agent calls the unlock client directly, through a shell, and through an external helper.
- Agent edits, replaces, renames, or symlinks policy files and their parent directory.
- Agent changes `HOME`, XDG paths, environment variables, working directory, or CLI arguments to select another policy.
- User locks a path while an agent already holds a descriptor or is running under an older policy revision.
- Service crashes during a policy update or between update and session restart.
- An allowed hard link, snapshot, copy, or mount alias reaches the same content as a locked path.

## Milestone order

1. Finish the path and process tests for the current allowlist prototype.
2. Prototype a root-owned policy snapshot and grant validation, with no unlock operation. The feasibility spike now reads `/etc/aishield/locks` for this purpose, but installation and updates are manual and there is no service yet.
3. Add service-mediated lock and unlock. The prototype now has root-peer authorization; caller classification beyond root and user-presence authentication are still required for the product UX.
4. Track and restart affected sessions before claiming immediate locks.
5. Review the full attack surface independently before any release that invites users to protect sensitive files.
