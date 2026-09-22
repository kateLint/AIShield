# AIShield

AIShield is an experiment in keeping selected local files outside an AI agent's reach even when the agent's own interface grants permission. The first milestone is a Linux command-line sandbox with an explicit launch step. Mobile is a separate, vault-based product track.

**Status:** security prototype with a Linux allowlist launcher and root-only lock service, not a finished protection product. Lock changes do not stop already-running agents. Do not use it to safeguard real secrets yet.

Read [the v1 specification](docs/v1-spec.md), [trusted policy design](docs/trusted-policy-design.md), and [the Linux prototype notes](prototype/linux/README.md) before running it.
