//go:build large
package dlp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugSpecificFNs(t *testing.T) {
	p := loadProductionPipeline(t)
	ctx := context.Background()
	targets := map[string]bool{
		"HMAC-Based OTP Counter Seed":               true,
		"Phabricator Conduit API Token":             true,
		"Chainstack RPC Endpoint":                   true,
		"Jira/Atlassian API Token":                  true,
		"Python pip extra-index-url Credentials":    true,
		"Python conda authentication token":         true,
		"PHP CodeIgniter Encryption Key":            true,
		"PHP WordPress wp-config Authentication Salt": true,
		".NET Service Connection String":            true,
		"Chef Encrypted Data Bag Secret":            true,
		"Shell script curl Basic Auth":              true,
		"Gradle gradle.properties Auth":             true,
		"Sentry DSN with Secret Key":                true,
		"Marketo Munchkin ID":                       true,
		"ServiceNow Instance URL":                   true,
	}

	root := "testdata/corpus/true_positives"
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		data, _ := os.ReadFile(path)
		for _, ln := range strings.Split(string(data), "\n") {
			if ln == "" {
				continue
			}
			var s map[string]interface{}
			if err := json.Unmarshal([]byte(ln), &s); err != nil {
				continue
			}
			pname, _ := s["pattern"].(string)
			if !targets[pname] {
				continue
			}
			b64, _ := s["content_b64"].(string)
			c, _ := base64.StdEncoding.DecodeString(b64)
			res := p.Scan(ctx, string(c))
			snip := string(c)
			if len(snip) > 250 {
				snip = snip[:250]
			}
			fmt.Printf("[%v] %s matched=%s score=%d\n  %q\n", res.Blocked, pname, res.PatternName, res.Score, snip)
			targets[pname] = false
		}
		return nil
	})
}
