#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Linux VM. Do not run on a developer workstation.
# Tested target profile: Linux x86_64/aarch64, cgroup v2, Landlock ABI >= 6,
# root-owned KECHAA daemon, distinct unprivileged agent account.

python3 tools/certify_linux.py preflight --cgroup-root /sys/fs/cgroup/kechaa
python3 -m kechaa policy validate examples/linux-offline.yaml
python3 tools/demo_attack_defense.py

# Prepare cgroup subtree before starting the daemon, for example:
#   mkdir -p /sys/fs/cgroup/kechaa
#   chown root:root /sys/fs/cgroup/kechaa
#   chmod 700 /sys/fs/cgroup/kechaa
#   echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
#
# Start daemon in the VM with a generated Linux policy and run the LC-* cases
# listed by `tools/certify_linux.py plan`. Certification is complete only after
# LC-001..LC-013 execute and produce retained audit checkpoints.

