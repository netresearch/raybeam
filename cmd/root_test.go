package cmd

import "testing"

func TestFormatVersion(t *testing.T) {
	cases := []struct {
		name           string
		version, commit string
		want           string
	}{
		{
			name:    "version only (no commit)",
			version: "v1.2.3",
			commit:  "",
			want:    "v1.2.3",
		},
		{
			name:    "version + full commit — commit shortened",
			version: "v1.2.3",
			commit:  "abcdef1234567890",
			want:    "v1.2.3 (abcdef1)",
		},
		{
			name:    "version + short commit — kept as-is",
			version: "v1.2.3",
			commit:  "abc123",
			want:    "v1.2.3 (abc123)",
		},
		{
			name:    "dedupe when version == commit (untagged vcs fallback)",
			version: "abcdef1234567890",
			commit:  "abcdef1234567890",
			want:    "abcdef1234567890",
		},
		{
			name:    "unknown version with no commit",
			version: "unknown",
			commit:  "",
			want:    "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatVersion(tc.version, tc.commit); got != tc.want {
				t.Errorf("formatVersion(%q, %q) = %q, want %q", tc.version, tc.commit, got, tc.want)
			}
		})
	}
}
