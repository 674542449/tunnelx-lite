//go:build windows

package app

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func protect(input []byte) ([]byte, error)   { return crypt(input, false) }
func unprotect(input []byte) ([]byte, error) { return crypt(input, true) }
func crypt(input []byte, decrypt bool) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(input))}
	if len(input) > 0 {
		in.Data = &input[0]
	}
	var out windows.DataBlob
	var e error
	if decrypt {
		e = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		e = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if e != nil {
		return nil, e
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return append([]byte{}, unsafe.Slice(out.Data, int(out.Size))...), nil
}
