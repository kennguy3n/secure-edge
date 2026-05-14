package proxy

import "runtime"

// runtimeMemStats is a thin alias of runtime.MemStats used by
// TestReadScanBody_OverCapStreams. Re-aliasing keeps the test file
// free of an extra import for a single helper.
type runtimeMemStats = runtime.MemStats

func readMemStats(m *runtimeMemStats) {
	runtime.GC()
	runtime.ReadMemStats(m)
}
