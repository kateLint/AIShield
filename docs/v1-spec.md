# AIShield v1 product and security specification

## Product decision

The first user is a developer running local CLI agents on Linux. The first release uses explicit containment: `aishield run -- COMMAND`. AIShield does not automatically identify AI applications. A desktop GUI, Windows and macOS backends, and mobile apps are separate milestones.

## Security promise

For an agent launched in an AIShield domain, the operating system denies access to files outside the domain's granted filesystem roots. Permission given inside the agent does not expand those roots. The restriction applies to descendants that remain in the domain. The launcher refuses to run if it cannot install the sandbox.

This is intentionally narrower than “no AI can read this folder.” An agent started outside AIShield, an unrestricted external helper, a privileged attacker, an already-open descriptor, or a copy of data elsewhere falls outside the claim. Network access and IPC are not controlled in v1.

## Crucial design correction

Linux Landlock is an allow-rule system. An allow rule on a parent also grants access below it, so it cannot express an arbitrary nested “deny this child but otherwise allow its parent” rule. The initial domain therefore grants *specific roots* and refuses any grant that contains a locked path. A user must split broad workspace grants into narrower roots. This constraint belongs in the product UX and tests, not in a hidden policy compiler.

Landlock domains are additive and cannot be relaxed. A lock added after an agent starts does not retroactively change that agent. The eventual product must stop or restart affected sessions before reporting the new lock as enforced. Unlocking likewise takes effect in a new domain.

## V1 scope

1. Linux CLI with explicit agent launch and read/write root grants.
2. Persistent lock registry owned by the local user, with atomic updates and restrictive permissions.
3. A launcher that rejects overlapping grants, closes unintended inherited descriptors, installs Landlock, and executes the command.
4. Adversarial tests for direct access, descendants, symlinks, hard links, renames, pre-opened descriptors, and external helpers.
5. Clear status showing which launched sessions are protected and whether a lock requires restart.

The first code in `prototype/linux` is a smaller *feasibility spike*: it installs an explicit Landlock allowlist, closes inherited descriptors, and executes a command. It does not yet include the persistent lock registry, session tracking, authentication, audit logging, or the complete adversarial suite. It must not be marketed as the v1 product.

## Acceptance gates

- An unprivileged Linux user can run a shell with a selected read/write root.
- Direct reads outside the root fail, including from child and grandchild processes.
- Reads inside the root work; writes work only in a write-granted root.
- Symlinks into excluded areas fail.
- An inherited file descriptor to an excluded file is unavailable to the agent.
- Unsupported or disabled Landlock causes launch failure, never an unrestricted fallback.
- A nested lock inside a granted parent is rejected with a useful explanation.
- The supported kernel ABI and filesystem limitations are documented from test results.

## Mobile track

Android and iPhone use app isolation and document-sharing APIs rather than the desktop launch model. A mobile AIShield would manage a protected file vault and broker the user's sharing choices. It would only claim control over files it stores or serves, not a device-wide veto over every other app's files. Mobile discovery begins after the Linux security promise passes its acceptance gates.

## Next engineering decisions

Choose the Linux distribution/kernel baseline and decide whether the eventual product prioritizes a developer CLI or managed enterprise deployments. Resolve how the service identifies and terminates active domains before promising immediate lock changes. Network and IPC controls require separate threat models.
