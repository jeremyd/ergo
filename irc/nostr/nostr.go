// Copyright (c) 2024 Ergo Contributors
// released under the MIT license

package nostr

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

var (
	// NIP-05 identifier format: name@domain.tld
	nip05Regex = regexp.MustCompile(`^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// npub format (bech32 encoded pubkey)
	npubRegex = regexp.MustCompile(`^npub1[a-zA-Z0-9]{58}$`)

	// hex pubkey format (64 hex characters)
	hexPubkeyRegex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// IsNostrIdentifier checks if a string could be a nostr identifier (NIP-05 or pubkey)
func IsNostrIdentifier(identifier string) bool {
	return IsNIP05(identifier) || IsPubkey(identifier)
}

// IsValidNostrIdentifier validates a nostr identifier format
func IsValidNostrIdentifier(identifier string) bool {
	return IsNostrIdentifier(identifier)
}

// IsNIP05 checks if the identifier is a NIP-05 address
func IsNIP05(identifier string) bool {
	return nip05Regex.MatchString(identifier)
}

// IsPubkey checks if the identifier is a pubkey (npub or hex)
func IsPubkey(identifier string) bool {
	return IsNpub(identifier) || IsHexPubkey(identifier)
}

// IsNpub checks if the identifier is an npub (bech32) format
func IsNpub(identifier string) bool {
	return npubRegex.MatchString(identifier)
}

// IsHexPubkey checks if the identifier is a hex pubkey
func IsHexPubkey(identifier string) bool {
	return hexPubkeyRegex.MatchString(identifier)
}

// NormalizePubkey converts npub to hex format, returns hex pubkey as-is
func NormalizePubkey(pubkey string) (string, error) {
	fmt.Printf("[DEBUG] NormalizePubkey called with: '%s' (len=%d)\n", pubkey, len(pubkey))
	fmt.Printf("[DEBUG] IsHexPubkey: %v, IsNpub: %v\n", IsHexPubkey(pubkey), IsNpub(pubkey))
	
	if IsHexPubkey(pubkey) {
		fmt.Printf("[DEBUG] Treating as hex pubkey\n")
		return strings.ToLower(pubkey), nil
	}

	if IsNpub(pubkey) {
		fmt.Printf("[DEBUG] Treating as npub, decoding...\n")
		// Use go-nostr to decode npub
		prefix, data, err := nip19.Decode(pubkey)
		if err != nil {
			fmt.Printf("[DEBUG] nip19.Decode failed: %v\n", err)
			return "", ErrInvalidPubkeyFormat
		}
		fmt.Printf("[DEBUG] nip19.Decode success - prefix: %s, data type: %T\n", prefix, data)

		// Handle both string and []byte return types from nip19.Decode
		switch v := data.(type) {
		case []byte:
			if len(v) == 32 {
				hexResult := hex.EncodeToString(v)
				fmt.Printf("[DEBUG] Successfully converted npub bytes to hex: %s\n", hexResult)
				return hexResult, nil
			}
		case string:
			if len(v) == 64 {
				// Already a hex string, validate it
				if err := ValidateHexPubkey(v); err != nil {
					fmt.Printf("[DEBUG] Invalid hex pubkey from npub: %v\n", err)
					return "", ErrInvalidPubkeyFormat
				}
				fmt.Printf("[DEBUG] Successfully got hex string from npub: %s\n", v)
				return strings.ToLower(v), nil
			}
		}

		fmt.Printf("[DEBUG] Unexpected data format from nip19.Decode: %T, value: %v\n", data, data)
		return "", ErrInvalidPubkeyFormat
	}

	fmt.Printf("[DEBUG] Pubkey doesn't match hex or npub format\n")
	return "", ErrInvalidPubkeyFormat
}

// ValidateHexPubkey ensures a hex string is a valid pubkey
func ValidateHexPubkey(hexStr string) error {
	if len(hexStr) != 64 {
		return ErrInvalidPubkeyLength
	}

	_, err := hex.DecodeString(hexStr)
	if err != nil {
		return ErrInvalidHexFormat
	}

	return nil
}

// ValidatePrivateKey validates a hex private key
func ValidatePrivateKey(privkeyHex string) error {
	if len(privkeyHex) != 64 {
		return ErrInvalidPubkeyLength
	}

	_, err := hex.DecodeString(privkeyHex)
	if err != nil {
		return ErrInvalidHexFormat
	}

	return nil
}

// GetPubkeyFromPrivkey derives public key from private key using go-nostr
func GetPubkeyFromPrivkey(privkeyHex string) (string, error) {
	if len(privkeyHex) != 64 {
		return "", ErrInvalidPrivkeyLength
	}

	pubkey, err := nostr.GetPublicKey(privkeyHex)
	if err != nil {
		return "", err
	}

	return pubkey, nil
}

// HexToNpub converts a hex pubkey to npub format
func HexToNpub(hexPubkey string) (string, error) {
	if !IsHexPubkey(hexPubkey) {
		return "", ErrInvalidPubkeyFormat
	}

	// Encode as npub using nip19 (it expects hex string, not bytes)
	npub, err := nip19.EncodePublicKey(hexPubkey)
	if err != nil {
		return "", err
	}

	return npub, nil
}
