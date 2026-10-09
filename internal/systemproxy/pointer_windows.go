//go:build windows

package systemproxy

import "unsafe"

func uintptrPointer(v *uint16) uintptr { return uintptr(unsafe.Pointer(v)) }
