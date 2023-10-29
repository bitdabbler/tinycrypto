# tinycrypto (The Tiny Crypto Toolbox)

## Overview

`tinycrypto` provides a set of tools for encrypting and decrypting data. It is intentionally kept very minimal, to make it as simple as possible for developers, even without deep knowledge of cryptography.

## Usage

The basic API is simple. 

First, we need a 256-bit (32-byte) encryption key. This is our master secret that never appears anywhere in repo. It can be any 256-bit byte slice, but we provide an easy way to make one using a secret string.

```go
encryptionKey := HashForString("super secret encryption key string")
```

Alternatively, we could use a completely random 256-bit key.

```go
encryptionKey, err := GenerateRandomBytes(32)
if err != nil {
    fmt.Println(err)
}
```

Once we have an encryption key, we can then use that value to encrypt and decrypt any slice of bytes.

```go
secretToProtect := []byte("crown jewels")
encrypted, err := Encrypt(secretToProtect, encryptionKey)
if err != nil {
    fmt.Println(err)
}
fmt.Println(base64.RawStdEncoding.EncodeToString(encrypted))
```

To get the original value back, we need to decrypt it using the same encryption key.

```go
recoveredSecret, err := Decrypt(encrypted, encryptionKey)
if err != nil {
    fmt.Println(err)
}
fmt.Println(string(recoveredSecret)) // crown jewels
```

A second API, also intentionally minimalist, is based on using a `Keyset`. This is a container wrapping multiple `Key`s, to allow for the transparent rotation of encryption keys.

A `Key` wraps a 32-byte value used as an encryption key (as we saw above). Along with the value, it stores that `Key`'s creation and expiration timestamps (unix epoch).

```go
plaintext := []byte("this is my secret value that I must protect")
key, err := NewRandomKey()
if err != nil {
    fmt.Println(err)
}
keyset := &Keyset{Keys: []*Key{key}}
cipherText, err := keyset.Encrypt(plaintext)
if err != nil {
    fmt.Println(err)
}
```

Now let's say the want to start using a new key, but we still want to be able to
access the values encrypted with the old key, up until a certain moment in time.

```go
newKey, err := NewRandomKey()
if err != nil {
    fmt.Println(err)
}
days90 := time.Hour * 24 * 90
keyset.RotateIn(newKey,  days90)
```

From now on, anything that we encrypt with our keyset will be encrypted using the newKey. But we can also still decrypt our secret value, which was encrypted with the old key.

```go
decrypted, err := keyset.Decrypt(cipherText)
if err != nil {
    fmt.Println(err)
}
fmt.Println(string(decrypted)) // this is my secret value that I must protect
```

## Simple tip

When your application starts, pass in a "master secret". Hash the master secret to make it the a valid (master) encryption key. The master secret and master key are *NOT* stored in the application or backend, and are *NOT* used to encrypt secret values in your business domain. 

But then what do we use to encrypt values in the business domain?

Generate a new random encryption key. Let's call that the working encryption key. Encrypt secret values in your business domain with that working encryption key. Now, you'll need to persist that working encryption key so that it can be used across multiple instances or multiple sessions. This is where you use the master encryption key. Encrypt the working encryption key with the master encryption key, and only then share the (encrypted) working encryption key among instances or save it to a persistent store.
