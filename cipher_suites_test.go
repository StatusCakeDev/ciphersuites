package ciphersuites_test

import (
	"testing"

	"github.com/StatusCakeDev/ciphersuites"
)

func TestClassification(t *testing.T) {
	var tests = []struct {
		name           string
		classification ciphersuites.Classification
		expected       string
	}{
		{
			name:           "returns recommended",
			classification: ciphersuites.Recommended,
			expected:       "recommended",
		},
		{
			name:           "returns secure",
			classification: ciphersuites.Secure,
			expected:       "secure",
		},
		{
			name:           "returns weak",
			classification: ciphersuites.Weak,
			expected:       "weak",
		},
		{
			name:           "returns insecure",
			classification: ciphersuites.Insecure,
			expected:       "insecure",
		},
		{
			name:           "returns unknown",
			classification: ciphersuites.Unknown,
			expected:       "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := tt.classification.String()
			if classification != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, classification)
			}
		})
	}
}

func TestGetClassification(t *testing.T) {
	var tests = []struct {
		name           string
		cipherSuite    string
		classification ciphersuites.Classification
	}{
		{
			name:           "returns recommended",
			cipherSuite:    "TLS_AES_128_CCM_8_SHA256",
			classification: ciphersuites.Recommended,
		},
		{
			name:           "returns secure",
			cipherSuite:    "TLS_DHE_RSA_WITH_AES_128_CCM",
			classification: ciphersuites.Secure,
		},
		{
			name:           "returns weak",
			cipherSuite:    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
			classification: ciphersuites.Weak,
		},
		{
			name:           "returns insecure",
			cipherSuite:    "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
			classification: ciphersuites.Insecure,
		},
		{
			name:           "returns unknown",
			cipherSuite:    "fake cipher suite",
			classification: ciphersuites.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := ciphersuites.GetClassification(tt.cipherSuite)
			if classification != tt.classification {
				t.Errorf("expected %s, got %s", tt.classification, classification)
			}
		})
	}
}
