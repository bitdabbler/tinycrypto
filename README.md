# tinycrypto (The Tiny Crypto Toolbox)

## Overview

`tinycrypto` provides a set of tools for encrypting and decrypting data. It is intentionally kept very minimal, to make it as simple as possible for developers, even without deep knowledge of cryptography.

## Basic Usage

The basic API is simple. 

First, we need a 256-bit (32-byte) encryption key. `tinycrypto` provides two easy ways to make cryptographically secure encryption keys.

We can generate one using any string:

```go
import (
    // …
    “github.com/bitdabbler/tinycrypto”
) 
```

```go
encryptionKey := tinycrypto.HashForString("super secret encryption key string")
```

Or, we generate a completely random one:

```go
encryptionKey, err := tinycrypto.GenerateRandomBytes(32)
if err != nil {
    fmt.Println(err)
}
```

Now we can use our encryption key to encrypt and decrypt any slice of bytes:

```go
secretToProtect := []byte("crown jewels")
encrypted, err := tinycrypto.Encrypt(secretToProtect, encryptionKey)
if err != nil {
    fmt.Println(err)
}

// here we encode this base64 before printing
fmt.Println(base64.RawStdEncoding.EncodeToString(encrypted))
```

To get the original value back, we decrypt it using the same encryption key:

```go
recoveredSecret, err := tinycrypto.Decrypt(encrypted, encryptionKey)
if err != nil {
    fmt.Println(err)
}
fmt.Println(string(recoveredSecret)) // crown jewels
```

## Keysets

A second API, also intentionally minimalist, is based on using a `Keyset`. This is a container wrapping multiple `Key`s. This enables the simple, transparent rotation of encryption keys.

A `Key` wraps one of those raw 32-byte encryption keys we made earlier. It augments the raw key with creation and expiration timestamps (unix epoch).

```go
plaintext := []byte("this is my secret value that I must protect")

// we’ll let it generate a complete random Key for us
key, err := tinycrypto.NewRandomKey()
if err != nil {
    fmt.Println(err)
}

// and add that to a new Keyset
keyset := &Keyset{Keys: []*Key{key}}

// now we can use the Keyset methods to encrypt and decrypt values
cipherText, err := keyset.Encrypt(plaintext)
if err != nil {
    fmt.Println(err)
}
```

Now, imagine that we want to start using a new `Key`, but for defined transition period, we still be able to access the values encrypted with the old key:

```go
newKey, err := NewRandomKey()
if err != nil {
    fmt.Println(err)
}

// the current key we’re replacing will expireAfter 30 days
keyset.RotateIn(newKey, time.Hour * 24 * 30)
```

From now on, anything that we encrypt with our `Keyset` will be encrypted using the newest `Key`. But we can also still decrypt secrets that were encrypted with any older key that hasn’t expired yet.

```go
decrypted, err := keyset.Decrypt(cipherText)
if err != nil {
    fmt.Println(err)
}
fmt.Println(string(decrypted)) // this is my secret value that I must protect
```

## One Approach

When our service starts, we inject a "secret", and then immediately hash that secret to turn it into a valid encryption key, which we’ll call the `prime key`. We do **not** store the secret or the prime key in the code, or in the backend. And, we do **not** use the `prime key` to encrypt business. Instead, we generate a random key, our `working key`, that we use to encrypt and decrypt business values.

Now, we need to store the `working key` in a configuration service or a data store, to make it available across sessions and across different instances of our service. We use the `prime key` to encrypt the `working key` before persisting it, and to decrypt it when an instance starts up. This which ensures that our `prime key` was never stored anywhere, and minimizes its presence in memory.