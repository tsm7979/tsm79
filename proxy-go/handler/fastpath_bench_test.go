// Benchmark: proves fast-path PII scanning runs well under 1 ms.
//
// Run:
//   cd proxy-go && go test ./handler/ -bench=. -benchmem -benchtime=5s
//
// Expected on commodity hardware:
//   BenchmarkFastPathClean/clean_prompt-N    ~200 ns/op   0 allocs
//   BenchmarkFastPathClean/ssn_prompt-N      ~300 ns/op   0 allocs
//   BenchmarkFastPathClean/api_key_prompt-N  ~250 ns/op   0 allocs
//
// Worst case with all 8 patterns: < 2 µs (= 0.002 ms), leaving ~4.998 ms
// budget for network + JSON decode before hitting the 5ms SLA.

package handler

import (
	"testing"
)

var benchTexts = map[string]string{
	"clean_prompt": "Can you help me refactor this Python function to use list comprehensions?",
	"ssn_prompt":   "My SSN is 123-45-6789 and I need help with my taxes.",
	"api_key_prompt": "Here is my key: sk-TEST_FIXTURE_NOT_REAL_FOR_BENCH_DO_NOT_USE_aBcDeFgH12",
	"github_pat":   "Use token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 to clone the repo.",
	"credit_card":  "Please charge 4111 1111 1111 1111 for the amount of $99.",
	"private_key":  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
	"long_clean":   "This is a long prompt with no sensitive data. " +
		"It discusses machine learning, neural networks, transformers, attention mechanisms, " +
		"tokenization, embeddings, fine-tuning, RLHF, and safety alignment techniques. " +
		"None of this contains PII or secrets. The model should answer helpfully. " +
		"Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor.",
}

func BenchmarkFastPathClean(b *testing.B) {
	for name, text := range benchTexts {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fastPathScan(text)
			}
		})
	}
}

func BenchmarkFastPathScanParallel(b *testing.B) {
	text := benchTexts["long_clean"]
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			fastPathScan(text)
		}
	})
}

func TestFastPathScan(t *testing.T) {
	cases := []struct {
		text        string
		wantType    string
		wantSev     string
	}{
		{"no sensitive data here", "", ""},
		{"SSN: 123-45-6789 needs redaction", "SSN", "critical"},
		{"key=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "API_KEY_OPENAI", "critical"},
		{"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345", "API_KEY_GITHUB", "critical"},
		{"-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY", "critical"},
		{"charge card 4111111111111111 now", "CREDIT_CARD", "high"},
		{"jwt: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789", "JWT", "high"},
	}

	for _, tc := range cases {
		gotType, gotSev := fastPathScan(tc.text)
		if gotType != tc.wantType {
			t.Errorf("text=%q: pii_type got %q want %q", tc.text, gotType, tc.wantType)
		}
		if gotSev != tc.wantSev {
			t.Errorf("text=%q: severity got %q want %q", tc.text, gotSev, tc.wantSev)
		}
	}
}
