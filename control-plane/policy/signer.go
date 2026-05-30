// Package policy — Ed25519 signing for policy snapshots.
//
// The control plane generates an Ed25519 keypair on first boot and persists it
// to ~/.tsm/policy-signing.{key,pub}.  Every GET /config/policy response
// includes:
//
//   X-TSM-Policy-Signature: <base64(sig)>
//   X-TSM-Policy-PubKey:    <base64(32-byte raw public key)>
//
// Dataplane nodes verify the signature before applying any policy update.
// Nodes that do not have the public key pinned yet can bootstrap it from the
// X-TSM-Policy-PubKey header on first contact, then pin it.
//
// Signature input: canonical JSON bytes of the Snapshot (json.Marshal output).
// Algorithm: Ed25519 (RFC 8032), deterministic — no nonce required.
package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	privKeyFile = ".tsm/policy-signing.key" // relative to $HOME
	pubKeyFile  = ".tsm/policy-signing.pub"
)

// Signer holds the Ed25519 keypair used to sign policy snapshots.
type Signer struct {
	priv   ed25519.PrivateKey
	Pub    ed25519.PublicKey
	PubB64 string // base64(32-byte raw public key) — safe to embed in HTTP headers
}

// NewSigner loads the signing keypair from ~/.tsm/ or generates a fresh one.
func NewSigner() (*Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	keyPath := filepath.Join(home, privKeyFile)
	pubPath := filepath.Join(home, pubKeyFile)

	priv, pub, err := loadKeyPair(keyPath, pubPath)
	if err != nil {
		// First boot: generate a new keypair.
		slog.Info("policy signer: no existing key found, generating new Ed25519 keypair",
			"key_path", keyPath)
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ed25519 key generation: %w", err)
		}
		if err := saveKeyPair(keyPath, pubPath, priv, pub); err != nil {
			return nil, err
		}
		slog.Info("policy signer: keypair persisted",
			"key_path", keyPath, "pub_path", pubPath)
	} else {
		slog.Info("policy signer: loaded existing keypair", "key_path", keyPath)
	}

	return &Signer{
		priv:   priv,
		Pub:    pub,
		PubB64: base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Sign returns a base64-encoded Ed25519 signature over the canonical JSON of snap.
//
// The signature covers exactly the bytes produced by json.Marshal(snap).
// Receivers must marshal the same struct and verify against that exact byte sequence.
func (s *Signer) Sign(snap *Snapshot) (string, error) {
	canonical, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("signer: marshal snapshot: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ── Key persistence ───────────────────────────────────────────────────────────

// loadKeyPair reads PEM-encoded key files and reconstructs the Ed25519 keypair.
//
// Private key PEM block:
//   Type:  "ED25519 PRIVATE KEY"
//   Bytes: 64-byte ed25519.PrivateKey (seed ‖ public key)
//
// Public key PEM block:
//   Type:  "ED25519 PUBLIC KEY"
//   Bytes: 32-byte ed25519.PublicKey
func loadKeyPair(keyPath, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "ED25519 PRIVATE KEY" {
		return nil, nil, errors.New("signer: invalid PEM type in private key file")
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("signer: private key length %d (expected %d)",
			len(block.Bytes), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(block.Bytes)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

func saveKeyPair(keyPath, pubPath string, priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("signer: mkdir %s: %w", filepath.Dir(keyPath), err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte(priv),
	})
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("signer: write private key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: []byte(pub),
	})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return fmt.Errorf("signer: write public key: %w", err)
	}

	return nil
}
