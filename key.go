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

package keyring

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"golang.org/x/sys/unix"

	"pault.ag/go/keyring/internals"
)

// Key is an asymmetric key loaded into the Linux Kernel Keyring.
type Key struct {
	// id is the Linux Kernel keyring id of the private (or public)
	// key handle.
	id int

	// opts contains the configuration for the Key in question.
	opts *Options
}

// ID will return the underlying Kernel Keyring ID
func (k Key) ID() int {
	return k.id
}

// KeySize will return the key size (for RSA, in bits) reported by the
// Linux Kernel.
func (k Key) KeySize() (int, error) {
	q, err := internals.PkeyQuery(k.id, "")
	if err != nil {
		return 0, err
	}
	return int(q.KeySize), nil
}

// Public implements the crypto.Signer interface.
func (k Key) Public() crypto.PublicKey {
	return k.opts.getPublicKey()
}

func infoString(enc string, hash crypto.Hash) (string, error) {
	switch hash {
	case 0:
		return fmt.Sprintf("enc=%s", enc), nil
	case crypto.SHA256:
		return fmt.Sprintf("enc=%s hash=sha256", enc), nil
	default:
		return "", fmt.Errorf("keyring: unsupported algorithm type")
	}
}

// VerifyPKCS1v15 will request that the kernel verify that the key handled by the
// kernel be used to verify the signature provided comes from that public key.
func VerifyPKCS1v15(k *Key, hash crypto.Hash, hashed []byte, sig []byte) error {
	info, err := infoString("pkcs1", hash)
	if err != nil {
		return err
	}

	query, err := internals.PkeyQuery(k.id, info)
	if err != nil {
		return err
	}
	if query.SupportedOps&internals.OpSupportsVerify == 0 {
		return fmt.Errorf("keyring: key does not support verification")
	}

	return internals.PkeyVerify(k.id, info, hashed, sig)
}

// DecryptPKCS1v15 will use the private key held in the keyring to
// decrypt a PKCS1v15 encoded encrypted block of data to the key's
// public key.
func DecryptPKCS1v15(key *Key, enc []byte) ([]byte, error) {
	info, err := infoString("pkcs1", 0)
	if err != nil {
		return nil, err
	}

	query, err := internals.PkeyQuery(key.id, info)
	if err != nil {
		return nil, err
	}
	if query.SupportedOps&internals.OpSupportsDecrypt == 0 {
		return nil, fmt.Errorf("keyring: key does not support decryption")
	}

	msg := make([]byte, query.MaxDecryptedSize)
	i, err := internals.PkeyDecrypt(key.id, info, enc, msg)
	if err != nil {
		return nil, err
	}
	msg = msg[:i]
	return msg, nil
}

// EncryptPKCS1v15 will use the public key held in the keyring to
// encrypt a PKCS1v15 encoded block of data to the key.
func EncryptPKCS1v15(key *Key, msg []byte) ([]byte, error) {
	info, err := infoString("pkcs1", 0)
	if err != nil {
		return nil, err
	}

	query, err := internals.PkeyQuery(key.id, info)
	if err != nil {
		return nil, err
	}
	if query.SupportedOps&internals.OpSupportsEncrypt == 0 {
		return nil, fmt.Errorf("keyring: key does not support encryption")
	}

	// TODO(paultag): Is MaxDecryptedSize right here?
	enc := make([]byte, query.MaxDecryptedSize)
	i, err := internals.PkeyEncrypt(key.id, info, msg, enc)
	if err != nil {
		return nil, err
	}
	enc = enc[:i]
	return enc, nil
}

// Sign implements the crypto.Signer interface.
func (k Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// TODO(paultag): Verify that the key has a sane PublicKey.

	info, err := infoString("pkcs1", opts.HashFunc())
	if err != nil {
		return nil, err
	}

	query, err := internals.PkeyQuery(k.id, info)
	if err != nil {
		return nil, err
	}
	if query.SupportedOps&internals.OpSupportsSign == 0 {
		return nil, fmt.Errorf("keyring: key does not support signing")
	}
	sig := make([]byte, query.MaxSigSize)
	i, err := internals.PkeySign(k.id, info, digest, sig)
	if err != nil {
		return nil, err
	}
	sig = sig[:i]

	return sig, nil
}

// Options contains user configurable knobs that control how the
// key material is handled.
type Options struct {
	// PublicKey should be set when the crypto.Signer needs to return a valid
	// key from the Public() function that's part of the crypto.Signer interface.
	//
	// This isn't strictly needed for many operations, but it will throw Go code
	// for a loop in some cases. This should be set when using the Key as a
	// crypto.Signer.
	PublicKey crypto.PublicKey
}

func (o *Options) getPublicKey() crypto.PublicKey {
	if o == nil {
		return nil
	}
	return o.PublicKey
}

// AddCertificate will add an x.509 Certificate to the kernel keyring.
func (ring *Keyring) AddCertificate(name string, cert *x509.Certificate, opts *Options) (*Key, error) {
	if opts == nil {
		opts = &Options{}
	}
	opts.PublicKey = cert.PublicKey
	ringid, err := ring.keyID()
	if err != nil {
		panic(err)
	}
	id, err := unix.AddKey("asymmetric", name, cert.Raw, ringid)
	if err != nil {
		return nil, err
	}
	key := Key{
		id:   id,
		opts: opts,
	}
	return &key, nil
}

// AddKey will add a private key to the keyring. The key is added according
// to the knobs set in the Options struct.
func (ring *Keyring) AddKey(name string, priv crypto.PrivateKey, opts *Options) (*Key, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pkeyable, ok := priv.(interface {
		Public() crypto.PublicKey
	})
	if !ok {
		return nil, fmt.Errorf("keyring: can't get private key's public key")
	}
	pub := pkeyable.Public()

	if opts == nil {
		opts = &Options{}
	}
	opts.PublicKey = pub

	ringid, err := ring.keyID()
	if err != nil {
		panic(err)
	}
	id, err := unix.AddKey("asymmetric", name, privBytes, ringid)
	if err != nil {
		if err == unix.EBADMSG {
			return nil, fmt.Errorf("bad message: is the 'pkcs8_key_parser' module loaded?")
		}
		return nil, err
	}
	key := Key{
		id:   id,
		opts: opts,
	}
	return &key, nil
}

// LoadKey will set up the keyring.Key from a key that's already been
// loaded into the Kernel Keyring.
//
// The kernel doesn't allow the reading of a public key from a loaded private
// key (or maybe it does and I'm not quite so clever yet), so this requires
// explicitly passing a loaded crypto.PublicKey which *must* correspond to
// the private key in question.
//
// The public key really ought to be set in the Options struct
// passed in if the Key is to be used for crypto.Signer operation.
func (ring *Keyring) LoadKey(name string, opts *Options) (*Key, error) {
	ringid, err := ring.keyID()
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	id, err := unix.KeyctlSearch(ringid, "asymmetric", name, 0)
	if err != nil {
		return nil, err
	}

	return &Key{
		id:   id,
		opts: opts,
	}, nil
}

// UnlinkKey will unlink a key from the keyring.
func (ring *Keyring) UnlinkKey(key *Key) error {
	return ring.unlink(key.id)
}

// UnlinkKeyring will unlink a keyring from the keyring.
func (ring *Keyring) UnlinkKeyring(kring *Keyring) error {
	return ring.unlink(kring.id)
}

// unlink will unlink a key or keyring from the provided keyring.
func (ring *Keyring) unlink(id int) error {
	ringid, err := ring.keyID()
	if err != nil {
		return err
	}
	return internals.Unlink(id, ringid)
}

// vim: foldmethod=marker
