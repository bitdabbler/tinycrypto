// Package tinycrypto provides some very simple helpers for encrypting and
// decrypting data with minimal fuss, either directly, or through a `Keyset`,
// which allows working with multiple encryption keys easily when you want to be
// able to smoothly rotate new keys in over time.
package tinycrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// HashForString converts a string into a 256-bit hash, usable as a secret key
// for symmetric crypto. NOTE: This is for safely stored secret keys. Do NOT use
// this for passwords.
func HashForString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// Encrypt leverages AES-GCM authenticated encryption (encrypts and signs).
// https://en.wikipedia.org/wiki/Galois/Counter_Mode NOTE: This is for safely
// storing secret keys. If you need to hash a password, use the acrypt lib.
func Encrypt(val, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, val, nil), nil
}

// Decrypt decrypts an AES-GCM encrypted value.
func Decrypt(val []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(val) < nonceSize {
		return nil, errors.New("the cipher text value is too short")
	}
	nonce, val := val[:nonceSize], val[nonceSize:]
	return gcm.Open(nil, nonce, val, nil)
}

// A Keyset stores multiple keys, allowing clients to rotate keys if required.
// The Keysets get persisted in a name-value store, so the type of Key in a
// given Keyset is generally fixed/known based on the name used to fetch it. If
// clients need to support Keysets of various types on a given API (which get
// persisted using the same name), they can optionally provide a TypeID.
type Keyset struct {
	keys   []*Key
	TypeID int
	sync.RWMutex
}

// NewKeyset constructs a new, empty, Keyset.
func NewKeyset() *Keyset {
	return &Keyset{
		keys: make([]*Key, 0, 1),
	}
}

// NewKeysetWithKey constructs a new Keyset with provided Key installed.
func NewKeysetWithKey(k *Key) *Keyset {
	return &Keyset{
		keys: []*Key{k},
	}
}

// Key wraps an encryption key value to be used with `Keyset`s.
type Key struct {
	Value       []byte
	CreatedUnix int64
	ExpiresUnix int64
}

// NewRandomKey creates a `Key`, for use with `Keyset`s, with a random 32-byte
// key value, and sets the creation date.
func NewRandomKey() (*Key, error) {
	v, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("unable to generate new key: %w", err)
	}
	return NewKey(v), nil
}

// NewKey creates a `Key`, for use with `Keyset`'s, with the given 256-bit
// value, and sets the creation date.
func NewKey(key256 []byte) *Key {
	return &Key{
		Value:       key256,
		CreatedUnix: time.Now().Unix(),
	}
}

// Encrypt leverages AES-GCM authenticated encryption using the first encryption
// key in they Keyset.
func (ks *Keyset) Encrypt(val []byte) ([]byte, error) {
	ks.RLock()
	defer ks.RUnlock()

	if len(ks.keys) == 0 {
		return nil, errors.New("invalid keyset: empty")
	}
	k := ks.keys[0]
	if k.ExpiresUnix > 0 && k.ExpiresUnix < time.Now().Unix() {
		return nil, errors.New("no valid key in keyset")
	}
	return Encrypt(val, k.Value)
}

// Decrypt attempts to decrypt an AES-GCM encrypted value using each unexpired
// key in the given keyset until decryption is successful.
func (ks *Keyset) Decrypt(val []byte) (res []byte, err error) {
	ks.RLock()
	defer ks.RUnlock()

	now := time.Now().Unix()
	for _, k := range ks.keys {
		if k.ExpiresUnix > 0 && k.ExpiresUnix < now {
			continue
		}
		res, err = Decrypt(val, k.Value)
		if err == nil {
			return res, nil
		}
	}
	return nil, errors.New("no valid decryption key")
}

// CryptoKeyStore provides a generic interface for storing and retrieving
// cryptographic keys (that themselves should be encrypted at rest).
type CryptoKeyStore interface {
	GetCryptoKeyset(name string) (keyset *Keyset, err error)
	PutCryptoKeyset(name string, keyset *Keyset) (err error)
}

// GenerateRandomBytes generates cryptographically secure pseudo-random numbers.
func GenerateRandomBytes(n uint32) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return nil, fmt.Errorf("GenerateRandomBytes failed: %w", err)
	}
	return buf, nil
}

// RandUInt32 returns a randomly-generated BigEndian 32-bit unsigned integer. It
// uses the crypto package, and these values are frequently used as nonces.
func RandUInt32() (uint32, error) {
	buf, err := GenerateRandomBytes(1 << 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf), nil
}

// RotateIn adds the new Key to the first slot in the Keyset, and pushes the
// previous Keys back, maintaining the order. It also sets the expiration on the
// more recent previous key.
func (ks *Keyset) RotateIn(key *Key, expireAfter time.Duration) {
	keys := []*Key{key}
	ks.Lock()
	defer ks.Unlock()
	if len(ks.keys) > 0 {
		ks.keys[0].ExpiresUnix = time.Now().Add(expireAfter).Unix()
		keys = append(keys, ks.keys...)
	}
	ks.keys = keys
}

// Purge removes all any expired keys.
func (ks *Keyset) Purge() {
	ks.Lock()
	defer ks.Unlock()
	now := time.Now().Unix()
	end := 0
	for _, k := range ks.keys {
		if k.ExpiresUnix > 0 && k.ExpiresUnix < now {
			continue
		}
		ks.keys[end] = k
		end++
	}
	ks.keys = ks.keys[:end]
}
