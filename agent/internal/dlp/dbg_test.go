//go:build large
package dlp

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestDebugSentry(t *testing.T) {
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
	res := p.Scan(ctx, content)
	fmt.Printf("Blocked=%v Pattern=%q Score=%d\n", res.Blocked, res.PatternName, res.Score)
	// Print which patterns match
	for _, pat := range p.patterns {
		if !strings.Contains(pat.Name, "Sentry") {
			continue
		}
		fmt.Printf("Pat=%s sev=%s em=%v hw_req=%v hw=%v\n", pat.Name, pat.Severity, pat.EntropyMin, pat.RequireHotword, pat.Hotwords)
	}
}
