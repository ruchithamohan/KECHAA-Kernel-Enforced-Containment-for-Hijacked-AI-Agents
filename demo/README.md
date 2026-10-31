# KECHAA Safe Demonstration Package

This package is a neutral, reusable demonstration guide. It is not event-specific and does not claim Linux certification by itself.

## Demo Modes

### Mode A — Certified Linux Demo

Use only after LC-001 through LC-013 are executed in a disposable Linux VM.

Expected sequence:

1. Show VM environment and preflight output.
2. Start KECHAA with a synthetic policy and dedicated workspace.
3. Open a run contract for a synthetic agent.
4. Launch the agent through `kechaa agent launch`.
5. Perform a permitted workspace action.
6. Trigger a controlled malicious external effect request.
7. Show `tool_request` denial and posture tightening.
8. Attempt file/network/process bypass from inside the supervised process tree.
9. Show OS-level denial evidence.
10. Export audit log and checkpoint.
11. Quarantine/recover or close the run.
12. Clean up VM state and destroy the VM.

### Mode B — Control-Plane Fallback Demo

Use only when Linux is unavailable. State clearly that this is not OS-enforcement evidence.

```bash
python tools/demo_attack_defense.py
python tools/certify_linux.py run
```

Expected result:

- The demo shows a permitted grant, external effect denial, posture tightening, and follow-up action requiring approval.
- Certification run reports `certified=false` and exits nonzero outside Linux.

## Required Safety Controls

- Disposable Linux VM only for hostile tests.
- Synthetic workspaces under `/work` only.
- Synthetic secrets under `/outside` only.
- No host home mounts.
- No SSH agent forwarding.
- No cloud credentials.
- No Docker socket mounts.
- No unrestricted host filesystem mounts.

## Recovery

If the demo fails:

1. Stop the daemon.
2. Kill only processes inside the VM test cgroup.
3. Preserve logs and audit exports.
4. Mark the scenario FAIL or BLOCKED.
5. Destroy and recreate the disposable VM before retrying if containment state is uncertain.

Never convert a failed certification case into a passing result by editing expected output.
