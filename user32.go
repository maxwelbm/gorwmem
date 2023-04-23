package gorwmem

import (
	"syscall"
)

var (
	user32               = syscall.MustLoadDLL("user32.dll")
	procGetAsyncKeyState = user32.MustFindProc("GetAsyncKeyState")
)

// GetAsyncKeyState get the status of a specific keyboard key
func GetAsyncKeyState(vKey int) uint16 {
	ret, _, _ := procGetAsyncKeyState.Call(uintptr(vKey))
	return uint16(ret)
}

// IsKeyDown https://docs.microsoft.com/en-gb/windows/win32/inputdev/virtual-key-codes
func IsKeyDown(v int) bool {
	return GetAsyncKeyState(v) > 0
}
