// Copyright (c) 2024 Ergo Contributors
// released under the MIT license

package nostr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip17"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// DMConfig holds configuration for DM operations
type DMConfig struct {
	PrivateKey    string        // Hex-encoded private key for signing
	DefaultRelays []string      // Fallback relays if none discovered
	Timeout       time.Duration // Timeout for relay operations
	UserAgent     string        // User agent for HTTP requests
}

// SimpleKeyer implements nostr.Keyer interface for NIP-17
type SimpleKeyer struct {
	privateKey string
}

func (k *SimpleKeyer) GetPublicKey(ctx context.Context) (string, error) {
	return nostr.GetPublicKey(k.privateKey)
}

func (k *SimpleKeyer) SignEvent(ctx context.Context, event *nostr.Event) error {
	return event.Sign(k.privateKey)
}

func (k *SimpleKeyer) Encrypt(ctx context.Context, plaintext, recipientPubkey string) (string, error) {
	// Generate conversation key using NIP-44
	conversationKey, err := nip44.GenerateConversationKey(recipientPubkey, k.privateKey)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, conversationKey)
}

func (k *SimpleKeyer) Decrypt(ctx context.Context, ciphertext, senderPubkey string) (string, error) {
	// Generate conversation key using NIP-44
	conversationKey, err := nip44.GenerateConversationKey(senderPubkey, k.privateKey)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ciphertext, conversationKey)
}

// CreateNIP04DM creates a NIP-04 DM event with verification code
func CreateNIP04DM(recipientPubkey, senderPrivkey, account, code, serverName string) (*nostr.Event, error) {
	// Create the message content
	message := fmt.Sprintf("Account verification for %s\n\nAccount: %s\nVerification code: %s\n\nTo verify your account, issue the following command:\n/MSG NickServ VERIFY %s %s",
		serverName, account, code, account, code)

	// Compute shared secret for NIP-04 encryption
	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubkey, senderPrivkey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute shared secret: %v", ErrDMEncryptionFailed, err)
	}

	// Encrypt the message using NIP-04
	encryptedContent, err := nip04.Encrypt(message, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDMEncryptionFailed, err)
	}

	// Get sender pubkey from private key
	senderPubkey, err := nostr.GetPublicKey(senderPrivkey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Create the event
	event := &nostr.Event{
		PubKey:    senderPubkey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      4, // NIP-04 DM event kind
		Tags: nostr.Tags{
			{"p", recipientPubkey},
		},
		Content: encryptedContent,
	}

	// Sign the event
	if err := event.Sign(senderPrivkey); err != nil {
		return nil, err
	}

	// Detailed debug logging for comparison
	log.Printf("[NOSTR DEBUG] Created NIP-04 DM event: %+v", event)
	jsonEvent, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		log.Printf("[NOSTR DEBUG] Failed to marshal event to JSON: %v", err)
	} else {
		log.Printf("[NOSTR DEBUG] NIP-04 DM event JSON: %s", jsonEvent)
	}

	return event, nil
}

// CreateNIP17DM creates a NIP-17 DM event with verification code
func CreateNIP17DM(recipientPubkey, senderPrivkey, account, code, serverName string) (*nostr.Event, error) {
	// Create the message content
	message := fmt.Sprintf("Account verification for %s\n\nAccount: %s\nVerification code: %s\n\nTo verify your account, issue the following command:\n/MSG NickServ VERIFY %s %s",
		serverName, account, code, account, code)

	log.Printf("[NOSTR DEBUG] Creating NIP-17 DM")
	log.Printf("[NOSTR DEBUG] Recipient pubkey: %s", recipientPubkey)
	log.Printf("[NOSTR DEBUG] Message content: %s", message)

	// Create a SimpleKeyer instance
	keyer := &SimpleKeyer{privateKey: senderPrivkey}

	// Get sender pubkey for logging
	senderPubkey, err := nostr.GetPublicKey(senderPrivkey)
	if err != nil {
		log.Printf("[NOSTR DEBUG] Failed to derive sender pubkey: %v", err)
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	log.Printf("[NOSTR DEBUG] Sender pubkey: %s", senderPubkey)

	// Use nip17.PrepareMessage to create properly gift-wrapped events
	ctx := context.Background()
	toUs, toThem, err := nip17.PrepareMessage(
		ctx,
		message,
		nostr.Tags{}, // empty tags, the function will add the "p" tag
		keyer,
		recipientPubkey,
		nil, // no modify function
	)
	if err != nil {
		log.Printf("[NOSTR DEBUG] Failed to prepare NIP-17 message: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrDMEncryptionFailed, err)
	}

	log.Printf("[NOSTR DEBUG] NIP-17 events prepared successfully")
	log.Printf("[NOSTR DEBUG] toUs event - Kind: %d, ID: %s", toUs.Kind, toUs.ID)
	log.Printf("[NOSTR DEBUG] toThem event - Kind: %d, ID: %s", toThem.Kind, toThem.ID)

	// Marshal complete event to JSON for detailed inspection
	jsonEvent, err := json.MarshalIndent(toThem, "", "  ")
	if err != nil {
		log.Printf("[NOSTR DEBUG] Failed to marshal NIP-17 event to JSON: %v", err)
	} else {
		log.Printf("[NOSTR DEBUG] Complete NIP-17 event JSON: %s", jsonEvent)
	}

	// Return the toThem event (the one that goes to the recipient)
	return &toThem, nil
}

// SendVerificationDM sends a verification DM to a user
func SendVerificationDM(identifier, account, code, serverName string, config DMConfig) error {
	if config.PrivateKey == "" {
		return ErrNostrKeyNotConfigured
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// Resolve the identifier to a pubkey
	nip05Config := NIP05Config{
		Timeout:   config.Timeout,
		UserAgent: config.UserAgent,
	}

	pubkey, nip05Relays, err := ResolvePubkey(identifier, nip05Config)
	if err != nil {
		return fmt.Errorf("failed to resolve pubkey: %w", err)
	}

	// Discover inbox relays
	relayConfig := RelayConfig{
		DefaultRelays: config.DefaultRelays,
		Timeout:       config.Timeout,
		MaxRelays:     10,
	}

	// Combine NIP-05 relays with discovered relays
	allRelays := append(nip05Relays, config.DefaultRelays...)
	if len(allRelays) > 0 {
		relayConfig.DefaultRelays = allRelays
	}

	// Check if user has private relays (NIP-50 kind 10050)
	privateRelays, hasPrivateRelays, err := CheckPrivateRelays(ctx, pubkey, relayConfig)
	if err != nil {
		// Continue with regular flow if private relay check fails
		hasPrivateRelays = false
	}

	var dmEvent *nostr.Event
	var targetRelays []string

	if hasPrivateRelays && len(privateRelays) > 0 {
		log.Printf("Using NIP-17 DM for user with private relays")
		// Use NIP-17 DMs for users with private relays
		dmEvent, err = CreateNIP17DM(pubkey, config.PrivateKey, account, code, serverName)
		if err != nil {
			return fmt.Errorf("failed to create NIP-17 DM: %w", err)
		}
		targetRelays = privateRelays
		log.Printf("Targeting private relays: %v", targetRelays)
	} else {
		log.Printf("Using NIP-04 DM for regular user")
		// Use NIP-04 DMs for regular users
		dmEvent, err = CreateNIP04DM(pubkey, config.PrivateKey, account, code, serverName)
		if err != nil {
			return fmt.Errorf("failed to create NIP-04 DM: %w", err)
		}

		// Discover inbox relays for NIP-04
		inboxRelays, err := DiscoverInboxRelays(pubkey, relayConfig)
		if err != nil {
			return fmt.Errorf("failed to discover inbox relays: %w", err)
		}
		targetRelays = inboxRelays
		log.Printf("Targeting inbox relays: %v", targetRelays)
	}

	// Send to target relays with retry logic
	var lastErr error
	successCount := 0

	for _, relayURL := range targetRelays {
		// Try connecting and sending
		err := sendToRelayWithRetry(ctx, relayURL, *dmEvent, config.PrivateKey)
		if err != nil {
			lastErr = err
			continue
		}

		successCount++
	}

	if successCount == 0 {
		if lastErr != nil {
			return fmt.Errorf("%w: %v", ErrDMSendFailed, lastErr)
		}
		return ErrDMSendFailed
	}

	return nil
}

// sendToRelayWithRetry attempts to send a DM to a relay with retry logic for auth failures
func sendToRelayWithRetry(ctx context.Context, relayURL string, event nostr.Event, privkey string) error {
	log.Printf("[NOSTR DEBUG] Connecting to relay: %s", relayURL)
	
	// Create a separate timeout context for this relay connection (15 seconds)
	relayCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	// First attempt without auth
	relay, err := nostr.RelayConnect(relayCtx, relayURL)
	if err != nil {
		log.Printf("[NOSTR DEBUG] Failed to connect to %s: %v", relayURL, err)
		return fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()

	log.Printf("[NOSTR DEBUG] Attempting to publish to %s without auth", relayURL)
	// Try sending without auth first
	err = relay.Publish(relayCtx, event)
	if err == nil {
		log.Printf("[NOSTR DEBUG] Successfully published to %s without auth", relayURL)
		// Log the event that was successfully published
		eventJSON, jsonErr := json.MarshalIndent(event, "", "  ")
		if jsonErr != nil {
			log.Printf("[NOSTR DEBUG] Failed to marshal published event: %v", jsonErr)
		} else {
			log.Printf("[NOSTR DEBUG] Published event JSON: %s", eventJSON)
		}
		return nil // Success!
	}

	log.Printf("[NOSTR DEBUG] Publish failed on %s: %v", relayURL, err)
	// If we get an auth error, try with authentication
	if strings.Contains(err.Error(), "auth-required") || strings.Contains(err.Error(), "you must auth") {
		log.Printf("[NOSTR DEBUG] Auth required for %s, reconnecting with authentication", relayURL)
		// Close and reconnect with auth
		relay.Close()

		// Create a new timeout context for the auth connection
		authCtx, authCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer authCancel()

		relay, err = ConnectToRelay(authCtx, relayURL, privkey)
		if err != nil {
			log.Printf("[NOSTR DEBUG] Failed to connect with auth to %s: %v", relayURL, err)
			return fmt.Errorf("failed to connect with auth to relay %s: %w", relayURL, err)
		}
		defer relay.Close()

		log.Printf("[NOSTR DEBUG] Attempting to publish to %s with auth", relayURL)
		// Try sending again after auth
		err = relay.Publish(authCtx, event)
		if err != nil {
			log.Printf("[NOSTR DEBUG] Failed to publish to authenticated %s: %v", relayURL, err)
			return fmt.Errorf("failed to publish to authenticated relay %s: %w", relayURL, err)
		}

		log.Printf("[NOSTR DEBUG] Successfully published to %s with auth", relayURL)
		// Log the event that was successfully published
		eventJSON, jsonErr := json.MarshalIndent(event, "", "  ")
		if jsonErr != nil {
			log.Printf("[NOSTR DEBUG] Failed to marshal published event: %v", jsonErr)
		} else {
			log.Printf("[NOSTR DEBUG] Published event JSON: %s", eventJSON)
		}
		return nil
	}

	// Other error, return as-is
	log.Printf("[NOSTR DEBUG] Non-auth error on %s: %v", relayURL, err)
	return fmt.Errorf("failed to publish to relay %s: %w", relayURL, err)
}

// SendNIP04DM sends a NIP-04 DM to specific relays
func SendNIP04DM(ctx context.Context, event *nostr.Event, relays []string, privkey string) error {
	var lastErr error
	successCount := 0

	for _, relayURL := range relays {
		// Try connecting and sending
		err := sendToRelayWithRetry(ctx, relayURL, *event, privkey)
		if err != nil {
			lastErr = err
			continue
		}

		successCount++
	}

	if successCount == 0 {
		if lastErr != nil {
			return fmt.Errorf("%w: %v", ErrDMSendFailed, lastErr)
		}
		return ErrDMSendFailed
	}

	return nil
}

// SendNIP17DM sends a NIP-17 DM to private relays
func SendNIP17DM(ctx context.Context, event *nostr.Event, privateRelays []string, privkey string) error {
	var lastErr error
	successCount := 0

	for _, relayURL := range privateRelays {
		// Try connecting and sending
		err := sendToRelayWithRetry(ctx, relayURL, *event, privkey)
		if err != nil {
			lastErr = err
			continue
		}

		successCount++
	}

	if successCount == 0 {
		if lastErr != nil {
			return fmt.Errorf("%w: %v", ErrDMSendFailed, lastErr)
		}
		return ErrDMSendFailed
	}

	return nil
}
