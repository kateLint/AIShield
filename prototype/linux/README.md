# Linux Landlock feasibility spike

This program is a **research prototype**, not AIShield v1. It demonstrates an explicit, inherited Landlock filesystem allowlist. It has no lock database, GUI, audit trail, network sandbox, or session management.

Build on Linux with `make`. Run:

```sh
./aishield-proto --read /usr --read /bin --read /lib --read /etc --read "$HOME/project" --write "$HOME/project" -- /bin/sh
```

Use only roots that exist on your machine. `--write` also grants reading. The program rejects a root that contains a path passed with `--lock`; for example:

```sh
./aishield-proto --read "$HOME" --lock "$HOME/Private" -- /bin/sh
```

This fails deliberately. Landlock cannot subtract `~/Private` from a broad grant to `~`. Instead, grant the specific project folders the agent needs. `--lock` is only a configuration sanity check in this spike, not a persistent lock or an independent enforcement rule. Pre-existing hard links or copies inside allowed roots remain readable; this is a path-based boundary.

The launcher checks the Landlock ABI, creates its rules, rejects regular files and directories inherited on standard input/output/error, sets `no_new_privs`, restricts itself, closes inherited descriptors at 3 and above, then calls `execvp`. It fails closed on errors. Test on a disposable Linux account or VM. A child can still contact unrestricted services over IPC or the network; do not treat this as protection against all data paths.

The code compiled in a Linux Docker container on 2026-09-22, but Docker Desktop's Linux VM returned `ENOSYS` for the Landlock version probe, including with container seccomp disabled. Runtime enforcement therefore remains unverified and needs a Linux host or VM with Landlock enabled.

Run `python3 test_aishield.py -v` on a Linux host after building. The tests cover allowed and denied reads, descendants, symlinks, write grants, inherited descriptors, and overlapping roots. The GitHub Actions workflow runs the same tests on an Ubuntu runner. A runner without Landlock fails the tests instead of silently skipping them.
