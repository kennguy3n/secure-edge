# Secure Edge — Benchmarks

Captured on an AMD EPYC 7763 (4 logical cores) Linux runner with Go
1.25.x and `-benchtime=2s`. Numbers are indicative — re-run on the
target hardware before drawing conclusions.

Reproduce with:

```bash
cd agent
go test -run='^$' -bench=. -benchtime=2s \
  ./internal/dlp/ ./internal/dns/ ./internal/stats/
```

## DLP pipeline

| Benchmark                  | ns/op    | B/op    | allocs/op | Throughput     |
|----------------------------|---------:|--------:|----------:|----------------|
| `PipelineScan` (small)     | 23,753   | 1,163   | 15        | ~42k scans/s   |
| `PipelineScanLarge` (100K) | 7.6M     | 116,997 | 20        | 14.17 MB/s     |
| `AhoCorasickBuild`         | 41,467   | 75,304  | 54        | rebuilds rule  |
| `Entropy`                  | 642.6    | 0       | 0         | ~1.5M tokens/s |

* `PipelineScan` is the per-request hot path; it stays sub-25µs at
  small payload sizes typical of proxy bodies.
* `PipelineScanLarge` exercises the full Aho-Corasick + regex passes
  on a ~100 KiB document; throughput tracks roughly linearly with
  input size, so a 10 KiB payload finishes in ~700µs.
* `AhoCorasickBuild` is amortised — it runs once per rule reload,
  which by default is hourly. 41µs per rebuild is negligible.
* `Entropy` is the cheapest gating step and has zero allocations.

## DNS resolver

| Benchmark             | ns/op | B/op | allocs/op | Notes            |
|-----------------------|------:|-----:|----------:|------------------|
| `DNSLookupAllowed`    | 554   | 440  | 6         | Allow → forward  |
| `DNSLookupBlocked`    | 114   | 168  | 2         | Deny → NXDOMAIN  |

Allowed lookups call into a fake forwarder; the real upstream cost
dominates in production. Blocked lookups never leave the agent and
finish in ~110ns.

## Stats counter

| Benchmark                       | ns/op | B/op | allocs/op | Notes                  |
|---------------------------------|------:|-----:|----------:|------------------------|
| `IncrementDNSQueries`           | 3.0   | 0    | 0         | Single-threaded atomic |
| `IncrementDNSQueriesParallel`   | 18    | 0    | 0         | 4 goroutines           |
| `Flush`                         | 528   | 0    | 0         | Drains in-mem → store  |

Counter increments are lock-free atomics; even at 100k qps the
counter is < 0.1 % of one CPU. `Flush` runs on the configured
flush interval (`stats_flush_interval`, default 60 s) and
dominates only when the store is on slow disk.

## Notes

These benchmarks intentionally favour the hot path (`Pipeline.Scan`,
`Resolver.HandleQuery`, `Counter.Increment*`). They are not a
substitute for end-to-end load testing — they exist so regressions
in the core data path show up early.
