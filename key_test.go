// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com> 2020-2021
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package keyring_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"pault.ag/go/keyring"

	"github.com/stretchr/testify/assert"
)

func checkAttrsWithPrivateKey(priv crypto.PrivateKey, size int) func(*testing.T) {
	return func(t *testing.T) {
		key, err := keyring.Session.AddKey("paultag-keyring-test-key", priv, nil)
		assert.NoError(t, err)
		keySize, err := key.KeySize()
		assert.NoError(t, err)
		assert.Equal(t, size, keySize)
		assert.NoError(t, keyring.Session.UnlinkKey(key))
	}
}

func TestAttributes(t *testing.T) {
	privR, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)
	t.Run("rsa1024", checkAttrsWithPrivateKey(privR, 1024))

	privR, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	t.Run("rsa2048", checkAttrsWithPrivateKey(privR, 2048))
}

func encryptWithPrivateKey(priv crypto.PrivateKey) func(*testing.T) {
	return func(t *testing.T) {
		key, err := keyring.Session.AddKey("paultag-keyring-test-key", priv, nil)
		assert.NoError(t, err)

		if key == nil {
			return
		}

		//
		//
		// TODO(paultag): This assumes RSA
		//
		//

		pubi, ok := priv.(interface {
			Public() crypto.PublicKey
		})
		assert.True(t, ok)
		pub := pubi.Public().(*rsa.PublicKey)

		// First, check encrypting with the Keyring, and checking via the
		// Keyring and Go's RSA module.

		secretMessage := []byte("send reinforcements, we're going to advance")
		ciphertext, err := keyring.EncryptPKCS1v15(key, secretMessage)
		assert.NoError(t, err)

		plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, secretMessage, plaintext)

		plaintext, err = keyring.DecryptPKCS1v15(key, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, secretMessage, plaintext)

		// Now, let's check encrypting with Go's RSA module and decrypt via
		// the Keyring and Go.

		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pub, secretMessage)
		assert.NoError(t, err)

		plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, priv.(*rsa.PrivateKey), ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, secretMessage, plaintext)

		plaintext, err = keyring.DecryptPKCS1v15(key, ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, secretMessage, plaintext)

		assert.NoError(t, keyring.Session.UnlinkKey(key))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	privR, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)
	t.Run("rsa1024", encryptWithPrivateKey(privR))

	privR, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	t.Run("rsa2048", encryptWithPrivateKey(privR))

	privR, err = rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)
	t.Run("rsa4096", encryptWithPrivateKey(privR))
}

func signWithPrivateKey(priv crypto.PrivateKey) func(*testing.T) {
	return func(t *testing.T) {
		pubi, ok := priv.(interface {
			Public() crypto.PublicKey
		})
		assert.True(t, ok)

		key, err := keyring.Session.AddKey("paultag-keyring-test-key", priv, nil)
		assert.NoError(t, err)

		if key == nil {
			return
		}

		h := sha256.New()
		h.Write([]byte("hello world this is some fancy ole' data"))
		digest := h.Sum(nil)

		sig, err := key.Sign(
			nil,
			digest,
			crypto.SHA256,
		)
		assert.NoError(t, err)

		// the following assume RSA only; this needs to be changed
		// if ECDSA is ever re-enabled.
		assert.NoError(t, keyring.VerifyPKCS1v15(key, crypto.SHA256, digest, sig))

		pub := pubi.Public().(*rsa.PublicKey)
		assert.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig))

		assert.NoError(t, keyring.Session.UnlinkKey(key))
	}
}

func TestAddSignVerify(t *testing.T) {
	privR, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)
	t.Run("rsa1024", signWithPrivateKey(privR))

	privR, err = rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	t.Run("rsa2048", signWithPrivateKey(privR))

	privR, err = rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err)
	t.Run("rsa4096", signWithPrivateKey(privR))

	// privE, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	// assert.NoError(t, err)
	// t.Run("ecdsa224", signWithPrivateKey(privE))
	// privE, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// assert.NoError(t, err)
	// t.Run("ecdsa256", signWithPrivateKey(privE))
	// privE, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// assert.NoError(t, err)
	// t.Run("ecdsa384", signWithPrivateKey(privE))
	// privE, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	// assert.NoError(t, err)
	// t.Run("ecdsa521", signWithPrivateKey(privE))
}

func TestEncryptDecryptWithCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)

	ring := keyring.Session

	key, err := ring.AddKey("paultag-keyring-test-key", priv, nil)
	assert.NoError(t, err)

	if key == nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Company"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// For good measure, let's use the crypto.Signer interface under test :)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	assert.NoError(t, err)
	certKey, err := ring.AddCertificate("paultag-keyring-test-cert", cert, nil)
	assert.NoError(t, err)

	secretMessage := []byte("send reinforcements, we're going to advance")
	ciphertext, err := keyring.EncryptPKCS1v15(certKey, secretMessage)
	assert.NoError(t, err)

	_, err = keyring.DecryptPKCS1v15(certKey, ciphertext)
	assert.Error(t, err)

	plaintext, err := keyring.DecryptPKCS1v15(key, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, secretMessage, plaintext)

	assert.NoError(t, ring.UnlinkKey(key))
	assert.NoError(t, ring.UnlinkKey(certKey))
}

func TestAddSignVerifyWithCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	assert.NoError(t, err)

	ring := keyring.Session

	key, err := ring.AddKey("paultag-keyring-test-key", priv, nil)
	assert.NoError(t, err)

	if key == nil {
		return
	}

	h := sha256.New()
	h.Write([]byte("hello world this is some fancy ole' data"))
	digest := h.Sum(nil)

	// Now that we have a good signature from the key, let's load only the
	// *public* key into the keyctl keyring, and check that the signature
	// matches.

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Company"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// For good measure, let's use the crypto.Signer interface under test :)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	assert.NoError(t, err)
	certKey, err := ring.AddCertificate("paultag-keyring-test-cert", cert, nil)
	assert.NoError(t, err)

	_, err = certKey.Sign(nil, digest, crypto.SHA256)
	assert.Error(t, err)
	sig, err := key.Sign(nil, digest, crypto.SHA256)
	assert.NoError(t, err)

	assert.NoError(t, keyring.VerifyPKCS1v15(certKey, crypto.SHA256, digest, sig))

	assert.NoError(t, ring.UnlinkKey(key))
	assert.NoError(t, ring.UnlinkKey(certKey))
}

// vim: foldmethod=marker
