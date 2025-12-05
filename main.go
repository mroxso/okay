package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip86"
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	databaseURL := getEnv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/khatru-relay?sslmode=disable")

	sharedDB, err := sql.Open("postgres", databaseURL)
	if err != nil {
		panic(fmt.Sprintf("failed to open database connection: %v", err))
	}
	defer sharedDB.Close()

	sharedDB.SetMaxOpenConns(10)
	sharedDB.SetMaxIdleConns(5)
	sharedDB.SetConnMaxIdleTime(0)

	if err := sharedDB.Ping(); err != nil {
		panic(fmt.Sprintf("failed to ping database: %v", err))
	}

	// create the relay instance
	relay := khatru.NewRelay()

	// set up some basic properties (will be returned on the NIP-11 endpoint)
	relay.Info.Name = getEnv("RELAY_NAME", "okay nostr relay")
	relay.Info.PubKey = getEnv("RELAY_PUBKEY", "")
	relay.Info.Description = getEnv("RELAY_DESCRIPTION", "this is a custom nostr relay")
	relay.Info.Icon = getEnv("RELAY_ICON", "https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fliquipedia.net%2Fcommons%2Fimages%2F3%2F35%2FSCProbe.jpg&f=1&nofb=1&ipt=0cbbfef25bce41da63d910e86c3c343e6c3b9d63194ca9755351bb7c2efa3359&ipo=images")
	relay.Info.Version = "0.0.1"
	relay.Info.Software = "https://github.com/mroxso/okay"

	// Initialize the event store database (it manages its own pool)
	db := postgresql.PostgresBackend{DatabaseURL: databaseURL}
	if err := db.Init(); err != nil {
		panic(err)
	}

	// Initialize the normal database manager for other data
	dbManager, err := NewDBManager(sharedDB)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize database manager: %v", err))
	}
	defer dbManager.Close()

	relay.StoreEvent = append(relay.StoreEvent, db.SaveEvent)
	relay.QueryEvents = append(relay.QueryEvents, db.QueryEvents)
	relay.CountEvents = append(relay.CountEvents, db.CountEvents)
	relay.DeleteEvent = append(relay.DeleteEvent, db.DeleteEvent)
	relay.ReplaceEvent = append(relay.ReplaceEvent, db.ReplaceEvent)

	// there are many other configurable things you can set
	relay.RejectEvent = append(relay.RejectEvent,
		// built-in policies
		policies.ValidateKind,

		// define your own policies
		policies.PreventLargeTags(100),
		// func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
		// 	if event.PubKey == "fa984bd7dbb282f07e16e7ae87b26a2a7b9b90b7246a44771f0cf5ae58018f52" {
		// 		return true, "we don't allow this person to write here"
		// 	}
		// 	return false, "" // anyone else can
		// },
		func(ctx context.Context, event *nostr.Event) (reject bool, msg string) {
			ownerPubKey := getEnv("RELAY_PUBKEY", "")
			// Check if the pubkey is allowed in the database
			isAllowed, err := dbManager.IsAllowedPubkey(event.PubKey)
			if err != nil {
				log.Printf("Error checking if pubkey is allowed: %v", err)
				return true, "error checking authorization"
			}

			if isAllowed || (ownerPubKey != "" && event.PubKey == ownerPubKey) {
				return false, "" // allowed pubkey or owner can write
			}
			return true, "this is a private relay, only the owner can write here"
		},
	)

	// you can request auth by rejecting an event or a request with the prefix "auth-required: "
	relay.RejectFilter = append(relay.RejectFilter,
		// built-in policies
		policies.NoComplexFilters,

		// define your own policies
		// func(ctx context.Context, filter nostr.Filter) (reject bool, msg string) {
		// 	ownerPubKey := getEnv("RELAY_PUBKEY", "")
		// 	if pubkey := khatru.GetAuthed(ctx); pubkey != "" {
		// 		log.Printf("request from %s\n", pubkey)
		// 		// Check if the authenticated pubkey is allowed in the database
		// 		isAllowed, err := dbManager.IsAllowedPubkey(pubkey)
		// 		if err != nil {
		// 			log.Printf("Error checking if pubkey is allowed: %v", err)
		// 			return true, "error checking authorization"
		// 		}

		// 		if isAllowed || (ownerPubKey != "" && pubkey == ownerPubKey) {
		// 			return false, "" // allowed pubkey or owner can read
		// 		}
		// 		return true, "this is a private relay, only authorized users can read here"
		// 	}
		// 	return true, "auth-required: only authenticated users can read from this relay"
		// 	// (this will cause an AUTH message to be sent and then a CLOSED message such that clients can
		// 	//  authenticate and then request again)
		// },
	)
	// check the docs for more goodies!

	// management endpoints
	relay.ManagementAPI.RejectAPICall = append(relay.ManagementAPI.RejectAPICall,
		func(ctx context.Context, mp nip86.MethodParams) (reject bool, msg string) {
			user := khatru.GetAuthed(ctx)
			ownerPubKey := getEnv("RELAY_PUBKEY", "")
			if user != ownerPubKey {
				return true, "go away, intruder"
			}
			return false, ""
		})

	// Pubkey management
	relay.ManagementAPI.AllowPubKey = func(ctx context.Context, pubkey string, reason string) error {
		return dbManager.AddAllowedPubkey(pubkey, reason)
	}

	relay.ManagementAPI.BanPubKey = func(ctx context.Context, pubkey string, reason string) error {
		// Remove from allowed list and add to banned list
		if err := dbManager.RemoveAllowedPubkey(pubkey); err != nil {
			// Ignore error if pubkey wasn't in allowed list
			log.Printf("Warning: could not remove pubkey from allowed list: %v", err)
		}
		return dbManager.BanPubKey(pubkey, reason)
	}

	relay.ManagementAPI.ListAllowedPubKeys = func(ctx context.Context) ([]nip86.PubKeyReason, error) {
		return dbManager.GetAllowedPubkeysWithReason()
	}

	relay.ManagementAPI.ListBannedPubKeys = func(ctx context.Context) ([]nip86.PubKeyReason, error) {
		return dbManager.GetBannedPubkeys()
	}

	// Event moderation
	relay.ManagementAPI.ListEventsNeedingModeration = func(ctx context.Context) ([]nip86.IDReason, error) {
		return dbManager.GetEventsNeedingModeration()
	}

	relay.ManagementAPI.AllowEvent = func(ctx context.Context, id string, reason string) error {
		return dbManager.AllowEvent(id, reason)
	}

	relay.ManagementAPI.BanEvent = func(ctx context.Context, id string, reason string) error {
		return dbManager.BanEvent(id, reason)
	}

	relay.ManagementAPI.ListBannedEvents = func(ctx context.Context) ([]nip86.IDReason, error) {
		return dbManager.GetBannedEvents()
	}

	relay.ManagementAPI.ListAllowedEvents = func(ctx context.Context) ([]nip86.IDReason, error) {
		return dbManager.GetAllowedEvents()
	}

	// Relay info management
	relay.ManagementAPI.ChangeRelayName = func(ctx context.Context, name string) error {
		if err := dbManager.SetRelayInfo("name", name); err != nil {
			return err
		}
		relay.Info.Name = name
		return nil
	}

	relay.ManagementAPI.ChangeRelayDescription = func(ctx context.Context, desc string) error {
		if err := dbManager.SetRelayInfo("description", desc); err != nil {
			return err
		}
		relay.Info.Description = desc
		return nil
	}

	relay.ManagementAPI.ChangeRelayIcon = func(ctx context.Context, icon string) error {
		if err := dbManager.SetRelayInfo("icon", icon); err != nil {
			return err
		}
		relay.Info.Icon = icon
		return nil
	}

	// Kind management
	relay.ManagementAPI.AllowKind = func(ctx context.Context, kind int) error {
		return dbManager.AllowKind(kind)
	}

	relay.ManagementAPI.DisallowKind = func(ctx context.Context, kind int) error {
		return dbManager.DisallowKind(kind)
	}

	relay.ManagementAPI.ListAllowedKinds = func(ctx context.Context) ([]int, error) {
		return dbManager.GetAllowedKinds()
	}

	relay.ManagementAPI.ListDisAllowedKinds = func(ctx context.Context) ([]int, error) {
		return dbManager.GetDisallowedKinds()
	}

	// IP blocking
	relay.ManagementAPI.BlockIP = func(ctx context.Context, ip net.IP, reason string) error {
		return dbManager.BlockIP(ip, reason)
	}

	relay.ManagementAPI.UnblockIP = func(ctx context.Context, ip net.IP, reason string) error {
		return dbManager.UnblockIP(ip)
	}

	relay.ManagementAPI.ListBlockedIPs = func(ctx context.Context) ([]nip86.IPReason, error) {
		return dbManager.GetBlockedIPs()
	}

	// Admin management
	relay.ManagementAPI.GrantAdmin = func(ctx context.Context, pubkey string, methods []string) error {
		return dbManager.GrantAdmin(pubkey, methods)
	}

	relay.ManagementAPI.RevokeAdmin = func(ctx context.Context, pubkey string, methods []string) error {
		return dbManager.RevokeAdmin(pubkey, methods)
	}

	// Stats
	relay.ManagementAPI.Stats = func(ctx context.Context) (nip86.Response, error) {
		// Get basic stats from the database
		var stats nip86.Response
		// You can extend this to include actual statistics
		// For now, return a simple response
		stats.Result = map[string]interface{}{
			"version": relay.Info.Version,
			"name":    relay.Info.Name,
		}
		return stats, nil
	}

	mux := relay.Router()
	// set up other http handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html")
		fmt.Fprintf(w, `Welcome! This is a <b>nostr</b> relay!`)
	})

	// start the server
	fmt.Println("running on :3334")
	http.ListenAndServe(":3334", relay)
}
