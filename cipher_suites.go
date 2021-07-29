package ciphersuites

// Classification specifies the security class a cipher suite falls under.
type Classification byte

const (
	// Unknown represents the security classification of an unknown cipher suite.
	Unknown Classification = iota
	// Recommended represents the security classification of a secure and
	// recommended
	// cipher suite.
	Recommended
	// Secure represents the security classification of a secure cipher suite.
	Secure
	// Weak represents the securty classification of a weak cipher suite.
	Weak
	// Insecure represents the security classification of an insecure cipher
	// suite.
	Insecure
)

func (c Classification) String() string {
	switch c {
	case Recommended:
		return "recommended"
	case Secure:
		return "secure"
	case Weak:
		return "weak"
	case Insecure:
		return "insecure"
	default:
		return "unknown"
	}
}

// Attributes represents the security attributes associated to a single cipher
// suite.
type Attributes struct {
	ProtocolVersion     string
	EncryptionAlgorithm string
	HashAlgorithm       string
	Classification      Classification
	TLSVersions         []string
}

// RecommendedCipherSuites is a list of secure cipher suites irecommended for
// use.
var RecommendedCipherSuites = map[string]Attributes{
	"TLS_AES_128_CCM_8_SHA256":                      Attributes{"TLS", "AES 128 CCM 8", "SHA256", Recommended, []string{"TLS1.3"}},
	"TLS_AES_128_CCM_SHA256":                        Attributes{"TLS", "AES 128 CCM", "SHA256", Recommended, []string{"TLS1.3"}},
	"TLS_AES_128_GCM_SHA256":                        Attributes{"TLS", "AES 128 GCM", "SHA256", Recommended, []string{"TLS1.3"}},
	"TLS_AES_256_GCM_SHA384":                        Attributes{"TLS", "AES 256 GCM", "SHA384", Recommended, []string{"TLS1.3"}},
	"TLS_CHACHA20_POLY1305_SHA256":                  Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Recommended, []string{"TLS1.3"}},
	"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256":           Attributes{"TLS", "AES 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384":           Attributes{"TLS", "AES 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256":          Attributes{"TLS", "ARIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384":          Attributes{"TLS", "ARIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256":      Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384":      Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_128_CCM":                  Attributes{"TLS", "AES 128 CCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256":           Attributes{"TLS", "AES 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_256_CCM":                  Attributes{"TLS", "AES 256 CCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384":           Attributes{"TLS", "AES 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256":          Attributes{"TLS", "ARIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384":          Attributes{"TLS", "ARIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256":      Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384":      Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256":     Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_128_CCM":              Attributes{"TLS", "AES 128 CCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8":            Attributes{"TLS", "AES 128 CCM 8", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       Attributes{"TLS", "AES 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_256_CCM":              Attributes{"TLS", "AES 256 CCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8":            Attributes{"TLS", "AES 256 CCM 8", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       Attributes{"TLS", "AES 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256":      Attributes{"TLS", "ARIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384":      Attributes{"TLS", "ARIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256":  Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384":  Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256":       Attributes{"TLS", "AES 128 CCM 8", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256":         Attributes{"TLS", "AES 128 CCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256":         Attributes{"TLS", "AES 128 GCM", "SHA256", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384":         Attributes{"TLS", "AES 256 GCM", "SHA384", Recommended, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256":   Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Recommended, []string{"TLS1.2"}},
}

// SecureCipherSuites is a list of secure cipher suites.
var SecureCipherSuites = map[string]Attributes{
	"TLS_DHE_RSA_WITH_AES_128_CCM":                Attributes{"TLS", "AES 128 CCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_128_CCM_8":              Attributes{"TLS", "AES 128 CCM 8", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":         Attributes{"TLS", "AES 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_256_CCM":                Attributes{"TLS", "AES 256 CCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_256_CCM_8":              Attributes{"TLS", "AES 256 CCM 8", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":         Attributes{"TLS", "AES 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256":        Attributes{"TLS", "ARIA 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384":        Attributes{"TLS", "ARIA 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256":    Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384":    Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECCPWD_WITH_AES_128_CCM_SHA256":          Attributes{"TLS", "AES 128 CCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECCPWD_WITH_AES_128_GCM_SHA256":          Attributes{"TLS", "AES 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECCPWD_WITH_AES_256_CCM_SHA384":          Attributes{"TLS", "AES 256 CCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_ECCPWD_WITH_AES_256_GCM_SHA384":          Attributes{"TLS", "AES 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       Attributes{"TLS", "AES 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       Attributes{"TLS", "AES 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256":      Attributes{"TLS", "ARIA 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384":      Attributes{"TLS", "ARIA 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256":  Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384":  Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Secure, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Secure, []string{"TLS1.2"}},
}

// WeakCipherSuites is a list of weak cipher suites.
var WeakCipherSuites = map[string]Attributes{
	"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA":             Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_DSS_WITH_AES_128_CBC_SHA":              Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_AES_128_CBC_SHA256":           Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_AES_128_GCM_SHA256":           Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_AES_256_CBC_SHA":              Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_AES_256_CBC_SHA256":           Attributes{"TLS", "AES 256 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_AES_256_GCM_SHA384":           Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256":          Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256":          Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384":          Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384":          Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA":         Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256":      Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256":      Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA":         Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256":      Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384":      Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_DSS_WITH_SEED_CBC_SHA":                 Attributes{"TLS", "SEED CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA":            Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_DSS_WITH_AES_128_CBC_SHA":             Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256":          Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_AES_256_CBC_SHA":             Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256":          Attributes{"TLS", "AES 256 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256":         Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384":         Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA":        Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA":        Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_DSS_WITH_SEED_CBC_SHA":                Attributes{"TLS", "SEED CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA":            Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA":             Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256":          Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_256_CBC_SHA":             Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384":          Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256":         Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384":         Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384":     Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA":            Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA":             Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":          Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA":             Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":          Attributes{"TLS", "AES 256 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256":         Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384":         Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA":        Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA":        Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_WITH_SEED_CBC_SHA":                Attributes{"TLS", "SEED CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA":             Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_RSA_WITH_AES_128_CBC_SHA":              Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_AES_128_CBC_SHA256":           Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_AES_128_GCM_SHA256":           Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_AES_256_CBC_SHA":              Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_AES_256_CBC_SHA256":           Attributes{"TLS", "AES 256 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_AES_256_GCM_SHA384":           Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256":          Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256":          Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384":          Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384":          Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA":         Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256":      Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256":      Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA":         Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256":      Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384":      Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_DH_RSA_WITH_SEED_CBC_SHA":                 Attributes{"TLS", "SEED CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA":         Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA":          Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256":       Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256":       Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA":          Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384":       Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384":       Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256":      Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256":      Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384":      Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384":      Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256":  Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256":  Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384":  Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384":  Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":        Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":         Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":      Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":         Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":      Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256":     Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384":     Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256": Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384": Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA":          Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA":           Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256":        Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA":           Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384":        Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256":       Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384":       Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256":   Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384":   Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":          Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":           Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":        Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":           Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":        Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256":       Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384":       Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256":   Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384":   Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA":           Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA":            Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256":         Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":         Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA":            Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384":         Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384":         Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256":        Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256":        Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384":        Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384":        Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256":    Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256":    Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384":    Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384":    Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_KRB5_WITH_3DES_EDE_CBC_SHA":               Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_WITH_IDEA_CBC_SHA":                   Attributes{"TLS", "IDEA CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_PSK_DHE_WITH_AES_128_CCM_8":               Attributes{"TLS", "AES 128 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_DHE_WITH_AES_256_CCM_8":               Attributes{"TLS", "AES 256 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_3DES_EDE_CBC_SHA":                Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_PSK_WITH_AES_128_CBC_SHA":                 Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_AES_128_CBC_SHA256":              Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_AES_128_CCM":                     Attributes{"TLS", "AES 128 CCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_AES_128_CCM_8":                   Attributes{"TLS", "AES 128 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_AES_128_GCM_SHA256":              Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_AES_256_CBC_SHA":                 Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_AES_256_CBC_SHA384":              Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_AES_256_CCM":                     Attributes{"TLS", "AES 256 CCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_AES_256_CCM_8":                   Attributes{"TLS", "AES 256 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_AES_256_GCM_SHA384":              Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_ARIA_128_CBC_SHA256":             Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_ARIA_128_GCM_SHA256":             Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_ARIA_256_CBC_SHA384":             Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_ARIA_256_GCM_SHA384":             Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256":         Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256":         Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384":         Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384":         Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256":        Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA":            Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_RSA_PSK_WITH_AES_128_CBC_SHA":             Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256":          Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256":          Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_AES_256_CBC_SHA":             Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384":          Attributes{"TLS", "AES 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384":          Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256":         Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256":         Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384":         Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384":         Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256":     Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256":     Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384":     Attributes{"TLS", "CAMELLIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384":     Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256":    Attributes{"TLS", "CHACHA20 POLY1305", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_RSA_WITH_AES_128_CBC_SHA":                 Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_AES_128_CBC_SHA256":              Attributes{"TLS", "AES 128 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_128_CCM":                     Attributes{"TLS", "AES 128 CCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_128_CCM_8":                   Attributes{"TLS", "AES 128 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_128_GCM_SHA256":              Attributes{"TLS", "AES 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_256_CBC_SHA":                 Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_AES_256_CBC_SHA256":              Attributes{"TLS", "AES 256 CBC", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_256_CCM":                     Attributes{"TLS", "AES 256 CCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_256_CCM_8":                   Attributes{"TLS", "AES 256 CCM 8", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_AES_256_GCM_SHA384":              Attributes{"TLS", "AES 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_ARIA_128_CBC_SHA256":             Attributes{"TLS", "ARIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_ARIA_128_GCM_SHA256":             Attributes{"TLS", "ARIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_ARIA_256_CBC_SHA384":             Attributes{"TLS", "ARIA 256 CBC", "SHA384", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_ARIA_256_GCM_SHA384":             Attributes{"TLS", "ARIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA":            Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256":         Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256":         Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA":            Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256":         Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384":         Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Weak, []string{"TLS1.2"}},
	"TLS_RSA_WITH_IDEA_CBC_SHA":                    Attributes{"TLS", "IDEA CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_RSA_WITH_SEED_CBC_SHA":                    Attributes{"TLS", "SEED CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA":        Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA":         Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA":         Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA":        Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA":         Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA":         Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA":            Attributes{"TLS", "3DES EDE CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1"}},
	"TLS_SRP_SHA_WITH_AES_128_CBC_SHA":             Attributes{"TLS", "AES 128 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SRP_SHA_WITH_AES_256_CBC_SHA":             Attributes{"TLS", "AES 256 CBC", "SHA", Weak, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
}

// InsecureCipherSuites is a list of insecure cipher suites.
var InsecureCipherSuites = map[string]Attributes{
	"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA":    Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5":       Attributes{"TLS EXPORT", "RC4 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA":        Attributes{"TLS", "3DES EDE CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":         Attributes{"TLS", "AES 128 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_AES_128_CBC_SHA256":      Attributes{"TLS", "AES 128 CBC", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_AES_128_GCM_SHA256":      Attributes{"TLS", "AES 128 GCM", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_AES_256_CBC_SHA":         Attributes{"TLS", "AES 256 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_AES_256_CBC_SHA256":      Attributes{"TLS", "AES 256 CBC", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_AES_256_GCM_SHA384":      Attributes{"TLS", "AES 256 GCM", "SHA384", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256":     Attributes{"TLS", "ARIA 128 CBC", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256":     Attributes{"TLS", "ARIA 128 GCM", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384":     Attributes{"TLS", "ARIA 256 CBC", "SHA384", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384":     Attributes{"TLS", "ARIA 256 GCM", "SHA384", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA":    Attributes{"TLS", "CAMELLIA 128 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256": Attributes{"TLS", "CAMELLIA 128 CBC", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256": Attributes{"TLS", "CAMELLIA 128 GCM", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA":    Attributes{"TLS", "CAMELLIA 256 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256": Attributes{"TLS", "CAMELLIA 256 CBC", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384": Attributes{"TLS", "CAMELLIA 256 GCM", "SHA384", Insecure, []string{"TLS1.2"}},
	"TLS_DH_anon_WITH_DES_CBC_SHA":             Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_anon_WITH_RC4_128_MD5":             Attributes{"TLS", "RC4 128", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_anon_WITH_SEED_CBC_SHA":            Attributes{"TLS", "SEED CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA":     Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_DSS_WITH_DES_CBC_SHA":              Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA":    Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_DSS_WITH_DES_CBC_SHA":             Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_PSK_WITH_NULL_SHA":                Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_NULL_SHA256":             Attributes{"TLS", "NULL", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_NULL_SHA384":             Attributes{"TLS", "NULL", "SHA384", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_PSK_WITH_RC4_128_SHA":             Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA":    Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DHE_RSA_WITH_DES_CBC_SHA":             Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA":     Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_DH_RSA_WITH_DES_CBC_SHA":              Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA":      Attributes{"TLS", "3DES EDE CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_ECDH_anon_WITH_AES_128_CBC_SHA":       Attributes{"TLS", "AES 128 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_anon_WITH_AES_256_CBC_SHA":       Attributes{"TLS", "AES 256 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_anon_WITH_NULL_SHA":              Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_anon_WITH_RC4_128_SHA":           Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_NULL_SHA":             Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_ECDSA_WITH_RC4_128_SHA":          Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_NULL_SHA":            Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":         Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_NULL_SHA":              Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_NULL_SHA256":           Attributes{"TLS", "NULL", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_NULL_SHA384":           Attributes{"TLS", "NULL", "SHA384", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_PSK_WITH_RC4_128_SHA":           Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_NULL_SHA":              Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":           Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_NULL_SHA":               Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_ECDH_RSA_WITH_RC4_128_SHA":            Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5":      Attributes{"TLS EXPORT", "DES CBC 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA":      Attributes{"TLS EXPORT", "DES CBC 40", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5":      Attributes{"TLS EXPORT", "RC2 CBC 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA":      Attributes{"TLS EXPORT", "RC2 CBC 40", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_EXPORT_WITH_RC4_40_MD5":          Attributes{"TLS EXPORT", "RC4 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_EXPORT_WITH_RC4_40_SHA":          Attributes{"TLS EXPORT", "RC4 40", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_WITH_3DES_EDE_CBC_MD5":           Attributes{"TLS", "3DES EDE CBC", "MD5", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_WITH_DES_CBC_MD5":                Attributes{"TLS", "DES CBC", "MD5", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_WITH_DES_CBC_SHA":                Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_WITH_IDEA_CBC_MD5":               Attributes{"TLS", "IDEA CBC", "MD5", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_KRB5_WITH_RC4_128_MD5":                Attributes{"TLS", "RC4 128", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_KRB5_WITH_RC4_128_SHA":                Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_NULL_WITH_NULL_NULL":                  Attributes{"TLS", "NULL", "NULL", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_NULL_SHA":                    Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_NULL_SHA256":                 Attributes{"TLS", "NULL", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_NULL_SHA384":                 Attributes{"TLS", "NULL", "SHA384", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_PSK_WITH_RC4_128_SHA":                 Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":        Attributes{"TLS EXPORT", "DES40 CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5":       Attributes{"TLS EXPORT", "RC2 CBC 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":           Attributes{"TLS EXPORT", "RC4 40", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_NULL_SHA":                Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_NULL_SHA256":             Attributes{"TLS", "NULL", "SHA256", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_NULL_SHA384":             Attributes{"TLS", "NULL", "SHA384", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_PSK_WITH_RC4_128_SHA":             Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_DES_CBC_SHA":                 Attributes{"TLS", "DES CBC", "SHA", Insecure, []string{"TLS1.0", "TLS1.1"}},
	"TLS_RSA_WITH_NULL_MD5":                    Attributes{"TLS", "NULL", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_NULL_SHA":                    Attributes{"TLS", "NULL", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_NULL_SHA256":                 Attributes{"TLS", "NULL", "SHA256", Insecure, []string{"TLS1.2"}},
	"TLS_RSA_WITH_RC4_128_MD5":                 Attributes{"TLS", "RC4 128", "MD5", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_RSA_WITH_RC4_128_SHA":                 Attributes{"TLS", "RC4 128", "SHA", Insecure, []string{"TLS1.0", "TLS1.1", "TLS1.2"}},
	"TLS_SM4_CCM_SM3":                          Attributes{"TLS", "SM4 CCM", "SM3", Insecure, []string{"TLS1.3"}},
	"TLS_SM4_GCM_SM3":                          Attributes{"TLS", "SM4 GCM", "SM3", Insecure, []string{"TLS1.3"}},
}

// GetClassification returns the security classification of a given cipher
// suite. If the cipher suite cannot be found then its classification is
// unknown.
func GetClassification(cipherSuite string) Classification {
	if cs, ok := RecommendedCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := SecureCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := WeakCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := InsecureCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	return Unknown
}
