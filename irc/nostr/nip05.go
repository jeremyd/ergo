// Copyright (c) 2024 Ergo Contributors
// released under the MIT license

package nostr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NIP05Response represents the JSON response from a .well-known/nostr.json endpoint
type NIP05Response struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

// NIP05Config holds configuration for NIP-05 resolution
type NIP05Config struct {
	Timeout   time.Duration
	UserAgent string
}

// ResolveNIP05 resolves a NIP-05 identifier to a pubkey
func ResolveNIP05(identifier string, config NIP05Config) (pubkey string, relays []string, err error) {
	if !IsNIP05(identifier) {
		return "", nil, ErrInvalidPubkeyFormat
	}

	parts := strings.Split(identifier, "@")
	if len(parts) != 2 {
		return "", nil, ErrInvalidPubkeyFormat
	}

	name, domain := parts[0], parts[1]

	// Construct the well-known URL
	url := fmt.Sprintf("https://%s/.well-known/nostr.json?name=%s", domain, name)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.Timeout,
	}

	// Make the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrNIP05HTTPError, err)
	}

	if config.UserAgent != "" {
		req.Header.Set("User-Agent", config.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrNIP05HTTPError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("%w: HTTP %d", ErrNIP05HTTPError, resp.StatusCode)
	}

	// Parse the JSON response
	var nip05Resp NIP05Response
	if err := json.NewDecoder(resp.Body).Decode(&nip05Resp); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrNIP05InvalidResponse, err)
	}

	// Look up the pubkey for this name
	pubkey, exists := nip05Resp.Names[name]
	if !exists {
		return "", nil, ErrNIP05PubkeyNotFound
	}

	// Validate the returned pubkey
	if err := ValidateHexPubkey(pubkey); err != nil {
		return "", nil, fmt.Errorf("%w: invalid pubkey in response", ErrNIP05InvalidResponse)
	}

	// Get relays if available
	if nip05Resp.Relays != nil {
		relays = nip05Resp.Relays[pubkey]
	}

	return pubkey, relays, nil
}

// ResolvePubkey resolves any nostr identifier to a hex pubkey
func ResolvePubkey(identifier string, config NIP05Config) (pubkey string, relays []string, err error) {
	// Debug logging to see what identifier we're trying to resolve
	fmt.Printf("[DEBUG] ResolvePubkey called with identifier: '%s'\n", identifier)
	fmt.Printf("[DEBUG] IsNIP05: %v, IsPubkey: %v, IsNpub: %v, IsHexPubkey: %v\n", 
		IsNIP05(identifier), IsPubkey(identifier), IsNpub(identifier), IsHexPubkey(identifier))
	
	if IsNIP05(identifier) {
		fmt.Printf("[DEBUG] Resolving as NIP-05 identifier\n")
		return ResolveNIP05(identifier, config)
	} else if IsPubkey(identifier) {
		fmt.Printf("[DEBUG] Resolving as pubkey, normalizing...\n")
		normalizedPubkey, err := NormalizePubkey(identifier)
		if err != nil {
			fmt.Printf("[DEBUG] NormalizePubkey failed: %v\n", err)
			return "", nil, err
		}
		fmt.Printf("[DEBUG] Normalized pubkey: %s\n", normalizedPubkey)
		return normalizedPubkey, nil, nil
	}

	fmt.Printf("[DEBUG] Identifier doesn't match any known format\n")
	return "", nil, ErrInvalidPubkeyFormat
}
