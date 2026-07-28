// Copyright (c) 2024 Ergo Contributors
// released under the MIT license

package nostr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// RelayConfig holds configuration for relay operations
type RelayConfig struct {
	DefaultRelays []string
	Timeout       time.Duration
	MaxRelays     int
}

// RelayInfo represents the NIP-11 relay information document
type RelayInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	PubKey      string `json:"pubkey"`
	Contact     string `json:"contact"`
	Limitation  struct {
		AuthRequired bool `json:"auth_required"`
	} `json:"limitation"`
}

// DiscoverInboxRelays discovers a user's inbox relays using NIP-65
func DiscoverInboxRelays(pubkey string, config RelayConfig) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// Try to get relays from NIP-65 (kind 10002 events)
	inboxRelays, err := queryRelayListMetadata(ctx, pubkey, config)
	if err == nil && len(inboxRelays) > 0 {
		return inboxRelays, nil
	}

	// Fallback to default relays if no inbox relays found
	if len(config.DefaultRelays) > 0 {
		return config.DefaultRelays, nil
	}

	return nil, ErrNoInboxRelaysFound
}

// queryRelayListMetadata queries for NIP-65 relay list metadata events
func queryRelayListMetadata(ctx context.Context, pubkey string, config RelayConfig) ([]string, error) {
	var inboxRelays []string

	// Connect to default relays to query for relay list metadata
	for _, relayURL := range config.DefaultRelays {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			continue // Try next relay
		}

		// Query for kind 10002 events (NIP-65 relay list metadata)
		filters := []nostr.Filter{{
			Authors: []string{pubkey},
			Kinds:   []int{10002},
			Limit:   1,
		}}

		sub, err := relay.Subscribe(ctx, filters)
		if err != nil {
			relay.Close()
			continue
		}

		// Wait for events with timeout
		done := false
		select {
		case event := <-sub.Events:
			relays := parseRelayListEvent(*event)
			inboxRelays = append(inboxRelays, relays...)
		case <-time.After(5 * time.Second):
			// Timeout waiting for event
		case <-ctx.Done():
			done = true
		}

		sub.Unsub()
		relay.Close()

		if done {
			break
		}

		if len(inboxRelays) > 0 {
			break // Found relays, no need to query more
		}
	}

	if len(inboxRelays) == 0 {
		return nil, ErrRelayDiscoveryFailed
	}

	return inboxRelays, nil
}

// parseRelayListEvent parses a NIP-65 relay list metadata event
func parseRelayListEvent(event nostr.Event) []string {
	var inboxRelays []string

	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "r" {
			relayURL := tag[1]

			// Check if this is an inbox relay (read capability)
			// If no marker is specified, assume both read and write
			isInbox := true
			if len(tag) >= 3 {
				marker := tag[2]
				isInbox = marker == "read" || marker == ""
			}

			if isInbox {
				inboxRelays = append(inboxRelays, relayURL)
			}
		}
	}

	return inboxRelays
}

// checkRelayRequiresAuth checks if a relay requires authentication via NIP-11
func checkRelayRequiresAuth(url string) bool {
	httpURL := strings.Replace(strings.Replace(url, "ws://", "http://", 1), "wss://", "https://", 1)

	client := &http.Client{
		Timeout: time.Second * 5,
	}

	req, err := http.NewRequest("GET", httpURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("Accept", "application/nostr+json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var info RelayInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return false
	}

	return info.Limitation.AuthRequired
}

// ConnectToRelay establishes a connection to a nostr relay with optional NIP-42 auth
func ConnectToRelay(ctx context.Context, url string, privkey string) (*nostr.Relay, error) {
	log.Printf("Connecting to relay: %s\n", url)

	relay, err := nostr.RelayConnect(ctx, url)
	if err != nil {
		log.Printf("Failed to connect to relay: %s, error: %v\n", url, err)
		return nil, fmt.Errorf("%w: %v", ErrRelayConnectionFailed, err)
	}

	log.Printf("Connected to relay: %s\n", url)

	// Check if relay requires auth before attempting authentication
	if privkey != "" && checkRelayRequiresAuth(url) {
		log.Printf("Relay requires authentication: %s\n", url)

		err = relay.Auth(ctx, func(authEvent *nostr.Event) error {
			// Validate challenge tag is present and not empty
			challengeTag := authEvent.Tags.Find("challenge")
			if len(challengeTag) < 2 || challengeTag[1] == "" || challengeTag[1] == " " {
				return fmt.Errorf("invalid or missing challenge in auth event")
			}
			return authEvent.Sign(privkey)
		})
		if err != nil {
			log.Printf("Failed to authenticate with relay: %s, error: %v\n", url, err)
			// Don't fail connection on auth error - some operations might still work
			// The relay will reject operations that require auth if needed
		} else {
			log.Printf("Authenticated with relay: %s\n", url)
		}
	}

	return relay, nil
}

// SendEventToRelay sends a nostr event to a relay
func SendEventToRelay(ctx context.Context, relay *nostr.Relay, event nostr.Event) error {
	err := relay.Publish(ctx, event)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDMSendFailed, err)
	}

	return nil
}

// CheckPrivateRelays checks if a user has private relays (NIP-50 kind 10050)
func CheckPrivateRelays(ctx context.Context, pubkey string, config RelayConfig) ([]string, bool, error) {
	var privateRelays []string

	// Connect to default relays to query for private relay list
	for _, relayURL := range config.DefaultRelays {
		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			continue
		}

		// Query for kind 10050 events (private relay list)
		filters := []nostr.Filter{{
			Authors: []string{pubkey},
			Kinds:   []int{10050},
			Limit:   1,
		}}

		sub, err := relay.Subscribe(ctx, filters)
		if err != nil {
			relay.Close()
			continue
		}

		// Wait for events
		done := false
		select {
		case event := <-sub.Events:
			privateRelays = parsePrivateRelayList(*event)
		case <-time.After(5 * time.Second):
			// Timeout
		case <-ctx.Done():
			done = true
		}

		sub.Unsub()
		relay.Close()

		if done {
			break
		}

		if len(privateRelays) > 0 {
			return privateRelays, true, nil
		}
	}

	return nil, false, nil
}

// parsePrivateRelayList parses a NIP-50 private relay list event
func parsePrivateRelayList(event nostr.Event) []string {
	var privateRelays []string

	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "relay" {
			privateRelays = append(privateRelays, tag[1])
		}
	}

	return privateRelays
}
