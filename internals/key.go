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

// Search will run a KEYCTL_SEARCH to resolve a key or keyring by
// their name.
func Search(ringid int, keyType, description string, destringid int) (int, error) {
	keyTypeBytes := []byte(keyType + "\x00")
	descriptionBytes := []byte(description + "\x00")
	keyTypeBytesPtr := uintptr(unsafe.Pointer(&keyTypeBytes[0]))
	descriptionBytesPtr := uintptr(unsafe.Pointer(&descriptionBytes[0]))

	r1, _, err := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_SEARCH,
		uintptr(ringid),
		keyTypeBytesPtr,
		descriptionBytesPtr,
		uintptr(destringid),
		0,
	)
	if err != 0 {
		return 0, err
	}
	return int(r1), nil
}

// Unlink will unlink a key or keyring from the provided keyring.
func Unlink(id, ringid int) error {
	_, _, err := unix.Syscall6(
		unix.SYS_KEYCTL,
		unix.KEYCTL_UNLINK,
		uintptr(id),
		uintptr(ringid),
		0, 0, 0,
	)
	if err != 0 {
		return err
	}
	return nil

}

// vim: foldmethod=marker
