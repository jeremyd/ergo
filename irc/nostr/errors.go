// Copyright (c) 2024 Ergo Contributors
// released under the MIT license

package nostr

import "errors"

var (
	// Identifier validation errors
	ErrInvalidNostrIdentifier = errors.New("invalid nostr identifier format")
	ErrInvalidPubkeyFormat    = errors.New("invalid pubkey format")
	ErrInvalidPubkeyLength    = errors.New("invalid pubkey length")
	ErrInvalidHexFormat       = errors.New("invalid hex format")
	ErrInvalidPrivkeyLength   = errors.New("invalid private key length")
	ErrInvalidNpubPrefix      = errors.New("invalid npub prefix")

	// NIP-05 resolution errors
	ErrNIP05ResolutionFailed = errors.New("NIP-05 resolution failed")
	ErrNIP05NotFound         = errors.New("NIP-05 address not found")
	ErrNIP05InvalidResponse  = errors.New("invalid NIP-05 response")
	ErrNIP05HTTPError        = errors.New("HTTP error during NIP-05 resolution")
	ErrNIP05PubkeyNotFound   = errors.New("pubkey not found in NIP-05 response")

	// Relay discovery errors
	ErrRelayDiscoveryFailed  = errors.New("relay discovery failed")
	ErrNoInboxRelaysFound    = errors.New("no inbox relays found")
	ErrRelayConnectionFailed = errors.New("relay connection failed")
	ErrRelayAuthFailed       = errors.New("relay authentication failed")

	// DM sending errors
	ErrDMSendFailed          = errors.New("DM send failed")
	ErrDMEncryptionFailed    = errors.New("DM encryption failed")
	ErrNostrKeyNotConfigured = errors.New("nostr private key not configured")

	// Decoding errors
	ErrNpubDecodingFailed = errors.New("npub decoding failed")
)
