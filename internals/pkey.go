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

package internals

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// PkeyParams contains KEYCTL_PKEY_SIGN syscall arguments.
type PkeyParams struct {
	// KeyID is the Keyring ID "handle" to the asymmetric key
	// loaded into the keyring.
	KeyID int32

	// InputLength indicates the length of the input data (usually
	// a hash digest).
	InputLength uint32

	// ArgumentLength indicates the length of the second argument -- which
	// in the case of a signature is the output signature buffer, but in
	// the case of verify, will be the signature being passed in.
	ArgumentLength uint32

	// reserved for future use
	_ [7]uint32
}

// PkeyQueryParams contains KEYCTL_PKEY_QUERY syscall arguments.
type PkeyQueryParams struct {
	// SupportedOps indicates what operations an asymmetric key
	// usages are valid.
	SupportedOps Op

	// KeySize indicates the key length, for RSA, the bit size (1024, 2048, 4096).
	KeySize uint32

	// MaxDataSize is the largest input data that can be handled.
	MaxDataSize uint16

	// MaxSigSize is the largest signature size that can be validated or generated.
	MaxSigSize uint16

	// MaxDecryptedSize is the largest data size that can be decrypted or encrypted.
	MaxDecryptedSize uint16

	_ [10]uint32
}

// Op is an Operation which can be done using an asymmetric key.
type Op uint32

var (
	// OpSupportsEncrypt indicates that a key can be encrypted to
	// (which does not require the private key material).
	OpSupportsEncrypt Op = 0x01

	// OpSupportsDecrypt indicates that a key can be used to decrypt
	// data encrypted to it. This requires the Private Key to be loaded
	// into the keyring.
	OpSupportsDecrypt Op = 0x02

	// OpSupportsSign indicates that a key can be used to sign data
	// using the private key held in memory.
	OpSupportsSign Op = 0x04

	// OpSupportsVerify indicates that a key can be used to verify
	// the signature produced by the private half of this key. This
	// does not require the private key material.
	OpSupportsVerify Op = 0x08
)

// PkeyQuery will query information about an asymmetric key loaded
// into the keyring. This contains information about the Supported
// Operations, as well as the key size information required to
// process signatures.
func PkeyQuery(id int, info string) (*PkeyQueryParams, error) {
	infoBytes := []byte(info + "\x00")
	infoBytesPtr := uintptr(unsafe.Pointer(&infoBytes[0]))

	pkeyQuery := &PkeyQueryParams{}
	_, _, err := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_PKEY_QUERY,
		uintptr(id),
		0,
		infoBytesPtr,
		uintptr(unsafe.Pointer(pkeyQuery)),
		0,
	)
	if err != 0 {
		return nil, err
	}
	return pkeyQuery, nil
}

func pkeyOpWithParams(
	op uintptr,
	info string,
	id int,
	in []byte,
	out []byte,
) (int, error) {
	infoBytes := []byte(info + "\x00")
	infoBytesPtr := uintptr(unsafe.Pointer(&infoBytes[0]))
	outPtr := uintptr(unsafe.Pointer(&out[0]))
	inPtr := uintptr(unsafe.Pointer(&in[0]))

	pkeySign := &PkeyParams{
		KeyID:          int32(id),
		InputLength:    uint32(len(in)),
		ArgumentLength: uint32(len(out)),
	}

	r1, _, err := unix.Syscall6(
		unix.SYS_KEYCTL,
		op,
		uintptr(unsafe.Pointer(pkeySign)),
		infoBytesPtr,
		inPtr,
		outPtr,
		0,
	)
	if err != 0 {
		return 0, err
	}
	return int(r1), nil
}

// PkeyEncrypt will call KEYCTL_PKEY_ENCRYPT with the provided arguments
// without doing any checks as to the reasonableness of the request.
func PkeyEncrypt(id int, info string, clear, cipher []byte) (int, error) {
	return pkeyOpWithParams(
		unix.KEYCTL_PKEY_ENCRYPT,
		info,
		id,
		clear,
		cipher,
	)
}

// PkeyDecrypt will call KEYCTL_PKEY_DECRYPT with the provided arguments
// without doing any checks as to the reasonableness of the request.
func PkeyDecrypt(id int, info string, clear, cipher []byte) (int, error) {
	return pkeyOpWithParams(
		unix.KEYCTL_PKEY_DECRYPT,
		info,
		id,
		clear,
		cipher,
	)
}

// PkeySign will call KEYCTL_PKEY_SIGN with the provided arguments
// without doing any checks as to the reasonableness of the request,
// such as the key operations indicating that it can actually, well,
// do a signature.
func PkeySign(id int, info string, hash, sig []byte) (int, error) {
	return pkeyOpWithParams(
		unix.KEYCTL_PKEY_SIGN,
		info,
		id,
		hash,
		sig,
	)
}

// PkeyVerify will call KEYCTL_PKEY_VERIFY with the provided arguments
// without doing any checks as to the reasonableness of the request,
// such as the key operations indicating that it can actually, well,
// do a signature.
func PkeyVerify(id int, info string, hash, sig []byte) error {
	infoBytes := []byte(info + "\x00")
	infoBytesPtr := uintptr(unsafe.Pointer(&infoBytes[0]))
	sigPtr := uintptr(unsafe.Pointer(&sig[0]))
	hashPtr := uintptr(unsafe.Pointer(&hash[0]))
	pkeyVerify := &PkeyParams{
		KeyID:          int32(id),
		InputLength:    uint32(len(hash)),
		ArgumentLength: uint32(len(sig)),
	}
	_, _, err := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_PKEY_VERIFY,
		uintptr(unsafe.Pointer(pkeyVerify)),
		infoBytesPtr,
		hashPtr,
		sigPtr,
		0,
	)
	if err != 0 {
		return err
	}
	return nil
}

// vim: foldmethod=marker
