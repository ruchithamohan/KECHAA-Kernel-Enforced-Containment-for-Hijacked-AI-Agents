# Performance and reproducibility

The current benchmark measures diagnostic Unix IPC and authorization cost. It executes no protected commands and is not a comparison with containers, VMs or another sandbox.

```bash
.venv/bin/python tools/benchmark.py --iterations 50 --output .local/benchmark.json
```

The output path must be new; choose a different filename for repeated runs. The script starts three fresh disposable daemons to measure startup, then a fourth for one warm-up and 50 sequential health/prepare/simulate iterations. Each prepare hashes the same canonical echo/cat/rm/Python inventory, writes SQLite state and signs audit records. Each grant is consumed. The daemon and all temporary state are removed afterward.

Results include raw samples, medians/min/max, OS/kernel, CPU/architecture, Python/SQLite/dependency versions, configuration, and a single daemon RSS sample if `ps` is available. Timing uses `perf_counter`. The reported sequential rate includes health plus prepare/simulate; it is not concurrent execution throughput. RSS is not peak memory, startup excludes dependency installation, and no human approval delay is measured.

Current local evidence is retained in [benchmark.json](../audit/adoption-evidence/benchmark.json). Read that file for actual hardware and raw values. `execution_overhead_ms` is deliberately null: measuring kernel execution overhead requires a prepared Linux environment and an appropriate unconfined workload baseline. This benchmark must not be relabeled as that measurement.

[Historical VM timings](completion.md#measured-performance-and-compatibility) used earlier code and software-emulated systems. They remain historical observations, not current native performance claims. To measure protected execution, use identical synthetic workloads and resource budgets, record setup and adoption separately from execution/cleanup, retain raw results and disclose unsupported paths.
