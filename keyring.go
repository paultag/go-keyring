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
	"golang.org/x/sys/unix"

	"pault.ag/go/keyring/internals"
)

var (
	// Group is the @g / group keyring.
	Group *Keyring = &Keyring{id: unix.KEY_SPEC_GROUP_KEYRING}

	// Session is the @s / session keyring.
	Session *Keyring = &Keyring{id: unix.KEY_SPEC_SESSION_KEYRING}

	// Thread is the @t / thread keyring.
	Thread *Keyring = &Keyring{id: unix.KEY_SPEC_THREAD_KEYRING}

	// User is the @u keyring.
	User *Keyring = &Keyring{id: unix.KEY_SPEC_USER_KEYRING}

	// UserSession is the @us keyring.
	UserSession *Keyring = &Keyring{id: unix.KEY_SPEC_USER_SESSION_KEYRING}
)

// Keyring indicates a keyring that can be used to manage the
// addition or removal of key material.
type Keyring struct {
	id int
}

// ID will return the underlying Kernel Keyring ID
func (ring *Keyring) ID() int {
	return ring.id
}

// FindKeyring will look up a keyring by its name, and return
// the ring ID.
func (ring *Keyring) FindKeyring(name string) (*Keyring, error) {
	ringid, err := ring.keyID()
	if err != nil {
		return nil, err
	}
	id, err := internals.Search(ringid, "keyring", name, 0)
	if err != nil {
		return nil, err
	}
	return &Keyring{id: id}, nil
}

// keyID will return the keyctl keyring id for the provided ID (in case
// it is a special ID)
func (ring *Keyring) keyID() (int, error) {
	return unix.KeyctlGetKeyringID(ring.id, false)
}

// AddKeyring will add a Keyring to the provided, well, Keyring.
func (ring *Keyring) AddKeyring(name string) (*Keyring, error) {
	ringid, err := ring.keyID()
	if err != nil {
		return nil, err
	}
	id, err := unix.AddKey("keyring", name, nil, ringid)
	if err != nil {
		return nil, err
	}
	return &Keyring{id: id}, nil
}

// vim: foldmethod=marker
