//go:build windows

package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
)

type wndClassEx struct {
	size, style            uint32
	wndProc                uintptr
	clsExtra, wndExtra     int32
	instance, icon, cursor uintptr
	background             uintptr
	menuName, className    *uint16
	iconSm                 uintptr
}

// watchSessionEnd keeps a hidden top-level window so Windows tells us about
// shutdown and sign-out, which Wails does not forward. onEnd runs before the
// process is terminated and must finish within a few seconds.
func watchSessionEnd(onEnd func()) {
	go func() {
		runtime.LockOSThread()
		user32 := windows.NewLazySystemDLL("user32.dll")
		defProc := user32.NewProc("DefWindowProcW")
		proc := windows.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
			switch msg {
			case wmQueryEndSession:
				return 1
			case wmEndSession:
				if wParam != 0 {
					onEnd()
				}
				return 0
			}
			r, _, _ := defProc.Call(hwnd, msg, wParam, lParam)
			return r
		})
		var instance windows.Handle
		if windows.GetModuleHandleEx(0, nil, &instance) != nil {
			return
		}
		name, _ := windows.UTF16PtrFromString("txlite-session-watch")
		class := wndClassEx{wndProc: proc, instance: uintptr(instance), className: name}
		class.size = uint32(unsafe.Sizeof(class))
		if r, _, _ := user32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&class))); r == 0 {
			return
		}
		hwnd, _, _ := user32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
		if hwnd == 0 {
			return
		}
		var msg [48]byte // MSG
		getMessage, translate, dispatch := user32.NewProc("GetMessageW"), user32.NewProc("TranslateMessage"), user32.NewProc("DispatchMessageW")
		for {
			r, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			translate.Call(uintptr(unsafe.Pointer(&msg[0])))
			dispatch.Call(uintptr(unsafe.Pointer(&msg[0])))
		}
	}()
}
