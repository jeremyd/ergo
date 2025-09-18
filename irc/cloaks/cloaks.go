// Copyright (c) 2019 Shivaram Lingamneni

package cloaks

import (
	"fmt"
	"net"
	"strings"

	"crypto/sha3"

	"github.com/ergochat/ergo/irc/nostr"
	"github.com/ergochat/ergo/irc/utils"
)

type CloakConfig struct {
	Enabled            bool
	EnabledForAlwaysOn bool `yaml:"enabled-for-always-on"`
	Netname            string
	CidrLenIPv4        int    `yaml:"cidr-len-ipv4"`
	CidrLenIPv6        int    `yaml:"cidr-len-ipv6"`
	NumBits            int    `yaml:"num-bits"`
	LegacySecretValue  string `yaml:"secret"`
	NostrHostnames     bool   `yaml:"nostr-hostnames"` // enable nostr-based hostnames for accounts registered with nostr

	secret   string
	numBytes int
	ipv4Mask net.IPMask
	ipv6Mask net.IPMask
}

func (cloakConfig *CloakConfig) Initialize() {
	// sanity checks:
	numBits := cloakConfig.NumBits
	if 0 == numBits {
		numBits = 64
	} else if 256 < numBits {
		numBits = 256
	}

	// derived values:
	cloakConfig.numBytes = numBits / 8
	// round up to the nearest byte
	if numBits%8 != 0 {
		cloakConfig.numBytes += 1
	}
	cloakConfig.ipv4Mask = net.CIDRMask(cloakConfig.CidrLenIPv4, 32)
	cloakConfig.ipv6Mask = net.CIDRMask(cloakConfig.CidrLenIPv6, 128)
}

func (cloakConfig *CloakConfig) SetSecret(secret string) {
	cloakConfig.secret = secret
}

// simple cloaking algorithm: normalize the IP to its CIDR,
// then hash the resulting bytes with a secret key,
// then truncate to the desired length, b32encode, and append the fake TLD.
func (config *CloakConfig) ComputeCloak(ip net.IP) string {
	if !config.Enabled {
		return ""
	} else if config.NumBits == 0 || config.secret == "" {
		return config.Netname
	}

	var masked net.IP
	v4ip := ip.To4()
	if v4ip != nil {
		masked = v4ip.Mask(config.ipv4Mask)
	} else {
		masked = ip.Mask(config.ipv6Mask)
	}
	return config.macAndCompose(masked)
}

func (config *CloakConfig) macAndCompose(b []byte) string {
	// SHA3(K || M):
	// https://crypto.stackexchange.com/questions/17735/is-hmac-needed-for-a-sha-3-based-mac
	input := make([]byte, len(config.secret)+len(b))
	copy(input, config.secret[:])
	copy(input[len(config.secret):], b)
	digest := sha3.Sum512(input)
	b32digest := utils.B32Encoder.EncodeToString(digest[:config.numBytes])
	return fmt.Sprintf("%s.%s", b32digest, config.Netname)
}

func (config *CloakConfig) ComputeAccountCloak(accountName string) string {
	// XXX don't bother checking EnabledForAlwaysOn, since if it's disabled,
	// we need to use the server name which we don't have
	if config.NumBits == 0 || config.secret == "" {
		return config.Netname
	}

	// pad with 16 initial bytes of zeroes, avoiding any possibility of collision
	// with a masked IP that could be an input to ComputeCloak:
	paddedAccountName := make([]byte, 16+len(accountName))
	copy(paddedAccountName[16:], accountName[:])
	return config.macAndCompose(paddedAccountName)
}

// ComputeNostrHostname generates a readable hostname from a nostr identifier
func (config *CloakConfig) ComputeNostrHostname(nostrIdentifier string) string {
	fmt.Printf("DEBUG: ComputeNostrHostname called with identifier: '%s'\n", nostrIdentifier)
	
	if nostrIdentifier == "" {
		fmt.Printf("DEBUG: Empty nostr identifier, returning netname: %s\n", config.Netname)
		return config.Netname
	}

	// Handle NIP-05 addresses (alice@example.com -> alice@example.com)
	if strings.Contains(nostrIdentifier, "@") {
		parts := strings.SplitN(nostrIdentifier, "@", 2)
		if len(parts) == 2 {
			// Return the full NIP-05 address as the hostname
			hostname := nostrIdentifier
			fmt.Printf("DEBUG: NIP-05 hostname generated: %s\n", hostname)
			return hostname
		}
	}

	// Handle npub format (npub1abc123... -> npub1abc123....nostr)
	if strings.HasPrefix(nostrIdentifier, "npub1") {
		// Use the full npub as hostname
		hostname := fmt.Sprintf("%s.nostr", nostrIdentifier)
		fmt.Printf("DEBUG: npub hostname generated: %s\n", hostname)
		return hostname
	}

	// Handle hex pubkey (3bf0c63f... -> convert to npub and use full npub.nostr)
	if len(nostrIdentifier) == 64 {
		// Convert hex pubkey to npub format
		npub, err := nostr.HexToNpub(nostrIdentifier)
		if err != nil {
			fmt.Printf("DEBUG: Failed to convert hex to npub: %v, using fallback\n", err)
			// Fallback to truncated hex if conversion fails
			truncated := nostrIdentifier[:8]
			hostname := fmt.Sprintf("%s.nostr", truncated)
			fmt.Printf("DEBUG: hex pubkey fallback hostname generated: %s\n", hostname)
			return hostname
		}
		hostname := fmt.Sprintf("%s.nostr", npub)
		fmt.Printf("DEBUG: hex pubkey converted to npub hostname: %s\n", hostname)
		return hostname
	}

	// Fallback to regular account cloak
	fallback := config.ComputeAccountCloak(nostrIdentifier)
	fmt.Printf("DEBUG: Using fallback account cloak: %s\n", fallback)
	return fallback
}
