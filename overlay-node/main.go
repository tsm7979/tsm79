// TSM overlay-node — the decentralized name layer (Phase 2a).
//
// A libp2p peer that stores/serves self-certifying `.tsm` name records in a
// Kademlia DHT. Records are byte-compatible with the Rust data plane's
// `overlay::NameRecord` (identical signing bytes + Ed25519), so either side can
// verify the other's records. The data plane queries this node's HTTP API when
// a name misses its local registry.
//
// This replaces the in-process registry with a real P2P mesh: a name published
// on one node propagates to others via the DHT, with no central authority.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// Record mirrors the Rust data plane's overlay::NameRecord on the wire.
type Record struct {
	Name      string `json:"name"`
	PubKey    string `json:"pubkey"`    // hex, 32 bytes
	Endpoint  string `json:"endpoint"`
	Sequence  uint64 `json:"sequence"`
	Signature string `json:"signature"` // hex, 64 bytes
}

// signingBytes reproduces EXACTLY overlay::NameRecord::signing_bytes in Rust,
// so a record signed on either side verifies on the other.
func signingBytes(name string, pubkey []byte, endpoint string, seq uint64) []byte {
	b := make([]byte, 0, 64+len(name)+len(endpoint))
	b = append(b, []byte("tsm-overlay-name-v1")...)
	b = append(b, 0)
	b = append(b, []byte(name)...)
	b = append(b, 0)
	b = append(b, pubkey...)
	b = append(b, 0)
	b = append(b, []byte(endpoint)...)
	b = append(b, 0)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	return append(b, s[:]...)
}

func (r *Record) verify() error {
	pk, err := hex.DecodeString(r.PubKey)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return errors.New("invalid pubkey")
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(pk, signingBytes(r.Name, pk, r.Endpoint, r.Sequence), sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func dhtKey(name string) string { return "/tsm/" + name }

// tsmValidator enforces the self-certifying rules inside the DHT: every stored
// value must be a validly-signed record whose name matches its key, and the
// highest sequence wins (anti-rollback).
type tsmValidator struct{}

func (tsmValidator) Validate(key string, value []byte) error {
	var rec Record
	if err := json.Unmarshal(value, &rec); err != nil {
		return err
	}
	if rec.Name != strings.TrimPrefix(key, "/tsm/") {
		return errors.New("record name does not match key")
	}
	return rec.verify()
}

func (tsmValidator) Select(_ string, values [][]byte) (int, error) {
	best, bestSeq := -1, int64(-1)
	for i, v := range values {
		var rec Record
		if json.Unmarshal(v, &rec) != nil || rec.verify() != nil {
			continue
		}
		if int64(rec.Sequence) > bestSeq {
			best, bestSeq = i, int64(rec.Sequence)
		}
	}
	if best < 0 {
		return 0, errors.New("no valid record")
	}
	return best, nil
}

func main() {
	ctx := context.Background()
	listen := envOr("TSM_OVERLAY_LISTEN", "/ip4/0.0.0.0/tcp/4001")
	apiAddr := envOr("TSM_OVERLAY_API", ":7700")

	h, err := libp2p.New(libp2p.ListenAddrStrings(listen))
	if err != nil {
		log.Fatalf("libp2p host: %v", err)
	}

	// A DEDICATED `/tsm` protocol prefix isolates this from the public IPFS DHT
	// (a sovereign, separate name space) and avoids the IPFS prefix's mandatory
	// /pk + /ipns validators — we only need the self-certifying `tsm` validator.
	kad, err := dht.New(ctx, h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix("/tsm"),
		dht.NamespacedValidator("tsm", tsmValidator{}),
	)
	if err != nil {
		log.Fatalf("dht: %v", err)
	}
	if err := kad.Bootstrap(ctx); err != nil {
		log.Printf("dht bootstrap: %v", err)
	}
	for _, addr := range splitNonEmpty(os.Getenv("TSM_OVERLAY_BOOTSTRAP")) {
		if err := connectPeer(ctx, h, addr); err != nil {
			log.Printf("bootstrap connect %s: %v", addr, err)
		} else {
			log.Printf("connected bootstrap peer %s", addr)
		}
	}

	log.Printf("overlay-node up: peer id %s", h.ID())
	for _, a := range h.Addrs() {
		log.Printf("  listening %s/p2p/%s", a, h.ID())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","peer_id":%q,"peers":%d}`, h.ID().String(), len(h.Network().Peers()))
	})
	mux.HandleFunc("/publish", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
			return
		}
		var rec Record
		if json.NewDecoder(r.Body).Decode(&rec) != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		if err := rec.verify(); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		val, _ := json.Marshal(rec)
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := kad.PutValue(cctx, dhtKey(rec.Name), val); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"published":true,"name":%q}`, rec.Name)
	})
	mux.HandleFunc("/resolve/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/resolve/")
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		val, err := kad.GetValue(cctx, dhtKey(name))
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"resolved":false,"name":%q}`, name), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(val)
	})

	log.Printf("overlay HTTP API on %s (/health /publish /resolve/<name>)", apiAddr)
	log.Fatal(http.ListenAndServe(apiAddr, mux))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func connectPeer(ctx context.Context, h host.Host, addr string) error {
	ma, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return err
	}
	pi, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return h.Connect(cctx, *pi)
}
