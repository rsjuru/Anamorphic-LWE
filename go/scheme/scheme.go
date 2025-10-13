package scheme

import (
	GSW "anamorphicLWE/DualGSW"
	DR "anamorphicLWE/DualRegev"
	PR "anamorphicLWE/PrimalRegev"
)

// Defines a common interface for all supported cryptographic schemes.
type Scheme interface {
	Name() string // Returns the scheme's name

	// Regular operations
	KeyGen(lam int) error // Key generation with security parameter lambda
	Enc(lam int) error    // Encryption
	Dec(lam int) error    // Decryption

	// Anamorphic operations
	AGen(lam int) error // Anamorphic key generation
	AEnc(lam int) error // Anamorphic encryption
	ADec(lam int) error // Anamorphic decryption
}

// Schemes is a global registry mapping scheme names to their corresponding objects
var Schemes = map[string]Scheme{}

// Adds a new cryptographic scheme implementation to the global registry
func Register(name string, s Scheme) {
	Schemes[name] = s
}

// Retrieves a scheme instance from the registry by its name.
func GetScheme(name string) Scheme {
	return Schemes[name]
}

// Automatically runs when the package is imported.
func init() {
	Register("DualRegev", DR.NewDualRegev())     // Register the Dual Regev scheme
	Register("PrimalRegev", PR.NewPrimalRegev()) // Register the Primal Regev scheme
	Register("DualGSW", GSW.NewDualGSW())        // Register the Dual GSW scheme
}
