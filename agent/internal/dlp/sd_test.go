//go:build large
package dlp

import (
	"context"
	"fmt"
	"testing"
)

func TestDebugSentry2(t *testing.T) {
	p := loadProductionPipeline(t)
	ctx := context.Background()
	content := `# production environment
NODE_ENV=production
LOG_LEVEL=info
# dsn credential for production deployment
https://04782369928ec35c5149a33bed448d0d:9313b65002d286605457aab2674650fb@o497732.ingest.sentry.io/4941123
# dsn was rotated above
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.prod.internal:4317
`
	// Manually find the Sentry pattern
	var sentryPat *Pattern
	for _, pat := range p.patterns {
		if pat.Name == "Sentry DSN with Secret Key" {
			sentryPat = pat
			break
		}
	}
	if sentryPat == nil {
		t.Fatal("not found")
	}
	// Try running just this pattern in isolation
	candidates := p.automaton.Scan(content)
	fmt.Printf("total candidates=%d\n", len(candidates))
	mineCount := 0
	for _, c := range candidates {
		if c.Pattern == sentryPat {
			mineCount++
			fmt.Printf("  cand offset=%d\n", c.Offset)
		}
	}
	fmt.Printf("sentry candidates=%d\n", mineCount)
	res := p.Scan(ctx, content)
	fmt.Printf("Scan result Blocked=%v Pattern=%q Score=%d\n", res.Blocked, res.PatternName, res.Score)
}
