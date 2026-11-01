# Roadmap

KECHAA's near-term scope is authorization-bound **offline** Linux command execution. This is a work ordering, not a promised release date or a list of implemented features.

| Priority | Outcome | Evidence needed before calling it done |
|---|---|---|
| 1 | Complete current Linux security acceptance | S3 real filesystem/mount scenarios; revocation during real worker startup/execution; restart/descendant cleanup on documented native environments |
| 2 | Reproducible developer checks | Observe CI across supported Python/OS matrix; resolve runner-specific failures without suppressing security probes; port older macOS-only fixtures in a reviewed contribution |
| 3 | One end-to-end real agent workflow | Exact agent/version, all execution paths, identity separation, cancellation, approvals and bypass attempts documented |
| 4 | Supported release operations | Monitored private security contact, versioned compatibility policy, authenticated release artifacts, retention and independent audit checkpoints |
| 5 | Broader evaluation data | Native execution cost/compatibility measurements and independent review of kernel/privilege boundaries |

No full MCP mediation, destination-aware networking, SQL authorization, Windows support or native macOS sandbox is promised. Add these only when a concrete workflow, threat model, maintenance owner and verification plan justify the expansion. Avoid implementing a framework adapter that merely forwards to unrestricted host execution.

Good first contributions are reproducible setup reports, documentation corrections and narrowly scoped examples. Security-sensitive work follows [contribution guidance](../CONTRIBUTING.md).
