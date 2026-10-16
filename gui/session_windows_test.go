//go:build windows

package main

import (
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSessionEndRestoresProxy(t *testing.T) {
	ended := make(chan struct{}, 1)
	watchSessionEnd(func() { ended <- struct{}{} })
	user32 := windows.NewLazySystemDLL("user32.dll")
	name, _ := windows.UTF16PtrFromString("txlite-session-watch")
	var hwnd uintptr
	for i := 0; i < 50 && hwnd == 0; i++ {
		hwnd, _, _ = user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(name)), 0)
		time.Sleep(20 * time.Millisecond)
	}
	if hwnd == 0 {
		t.Fatal("session window not created")
	}
	send := user32.NewProc("SendMessageW")
	if r, _, _ := send.Call(hwnd, wmQueryEndSession, 0, 0); r != 1 {
		t.Fatal("shutdown query refused")
	}
	send.Call(hwnd, wmEndSession, 0, 0) // cancelled shutdown: keep the proxy
	select {
	case <-ended:
		t.Fatal("restored on a cancelled shutdown")
	default:
	}
	send.Call(hwnd, wmEndSession, 1, 0)
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("session end not handled")
	}
}
