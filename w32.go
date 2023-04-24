package gorwmem

import (
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	STANDARD_RIGHTS_REQUIRED = 0x000F
	STANDARD_RIGHTS_READ     = 0x20000
	STANDARD_RIGHTS_WRITE    = 0x20000
	STANDARD_RIGHTS_EXECUTE  = 0x20000
	STANDARD_RIGHTS_ALL      = 0x1F0000
)

const SE_DEBUG_NAME = "SeDebugPrivilege"

const (
	Th32csSnapprocess  = 0x00000002
	MaxPath            = 260
	PROCESS_ALL_ACCESS = 2035711 //This is not recommended.
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx
const (
	// do not reorder
	TOKEN_ASSIGN_PRIMARY = 1 << iota
	TOKEN_DUPLICATE
	TOKEN_IMPERSONATE
	TOKEN_QUERY
	TOKEN_QUERY_SOURCE
	TOKEN_ADJUST_PRIVILEGES
	TOKEN_ADJUST_GROUPS
	TOKEN_ADJUST_DEFAULT
	TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT
	TOKEN_READ  = STANDARD_RIGHTS_READ | TOKEN_QUERY
	TOKEN_WRITE = STANDARD_RIGHTS_WRITE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT
	TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE
)

type (
	HANDLE  uintptr
	DWORD   uint32
	LONG    int32
	BOOL    int32
	HMODULE HANDLE
)

var (
	modkernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procCloseHandle              = modkernel32.NewProc("CloseHandle")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")

	modadvapi32               = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValue  = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
	procModule32First         = modkernel32.NewProc("Module32FirstW")
	procModule32Next          = modkernel32.NewProc("Module32NextW")
	procReadProcessMemory     = modkernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory    = modkernel32.NewProc("WriteProcessMemory")
)

func CreateToolhelp32Snapshot(flags, processId uint32) HANDLE {
	ret, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processId))

	if ret <= 0 {
		return HANDLE(0)
	}

	return HANDLE(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684839(v=vs.85).aspx
type PROCESSENTRY32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [MaxPath]uint16
}

func Process32First(snapshot HANDLE, procEntry *PROCESSENTRY32) (err error) {
	_snapshot := syscall.Handle(snapshot)
	//var _procEntry *syscall.ProcessEntry32

	err = syscall.Process32First(_snapshot, (*syscall.ProcessEntry32)(procEntry))

	//procEntry = PROCESSENTRY32(*_procEntry)

	return
}

func Process32Next(snapshot HANDLE, procEntry *PROCESSENTRY32) (err error) {
	_snapshot := syscall.Handle(snapshot)
	//var _procEntry *syscall.ProcessEntry32

	err = syscall.Process32Next(_snapshot, (*syscall.ProcessEntry32)(procEntry))

	//procEntry = PROCESSENTRY32(*_procEntry)

	return
}

func UTF16PtrToString(cstr *uint16) string {
	if cstr != nil {
		us := make([]uint16, 0, 256)
		for p := uintptr(unsafe.Pointer(cstr)); ; p += 2 {
			u := *(*uint16)(unsafe.Pointer(p))
			if u == 0 {
				return string(utf16.Decode(us))
			}
			us = append(us, u)
		}
	}

	return ""
}

func CloseHandle(object HANDLE) bool {
	ret, _, _ := procCloseHandle.Call(
		uintptr(object))
	return ret != 0
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle HANDLE, err error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	ret, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId))

	if ret == 0 {
		return 0, err
	}

	return HANDLE(ret), nil
}

func GetCurrentProcess() (pseudoHandle HANDLE, err error) {
	_handle, err := syscall.GetCurrentProcess()
	pseudoHandle = HANDLE(_handle)

	return
}

func OpenProcessToken(processHandle HANDLE, desiredAccess uint32, tokenHandle *HANDLE) bool {

	ret, _, _ := procOpenProcessToken.Call(
		uintptr(processHandle),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(tokenHandle)))

	return ret != 0
}

// Winnt.h
const (
	ANYSIZE_ARRAY = 1
)

// LUID https://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx
type LUID struct {
	LowPart  DWORD
	HighPart LONG
}

// LUID_AND_ATTRIBUTES https://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes DWORD
}

// TOKEN_PRIVILEGES https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
type TOKEN_PRIVILEGES struct {
	PrivilegeCount DWORD
	Privileges     [ANYSIZE_ARRAY]LUID_AND_ATTRIBUTES
}

func LookupPrivilegeValue(lpSystemName string, lpName string, lpLuid *LUID) bool {

	ret, _, _ := procLookupPrivilegeValue.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpSystemName))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpName))),
		uintptr(unsafe.Pointer(lpLuid)))

	return ret != 0
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
	SE_PRIVILEGE_VALID_ATTRIBUTES   = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS
)

func AdjustTokenPrivileges(tokenHandle HANDLE, disableAllPrivileges BOOL, newState *TOKEN_PRIVILEGES, bufferLength uint32, previousState *TOKEN_PRIVILEGES, returnLength *uint32) bool {
	ret, _, _ := procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(disableAllPrivileges),
		uintptr(unsafe.Pointer(newState)),
		uintptr(bufferLength),
		uintptr(unsafe.Pointer(previousState)),
		uintptr(unsafe.Pointer(returnLength)))
	return ret != 0
}

// CreateToolhelp32Snapshot flags
const (
	TH32CS_SNAPHEAPLIST = 0x00000001
	TH32CS_SNAPPROCESS  = 0x00000002
	TH32CS_SNAPTHREAD   = 0x00000004
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010
	TH32CS_INHERIT      = 0x80000000
	TH32CS_SNAPALL      = TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD
)

// MODULEENTRY32 http://msdn.microsoft.com/en-us/library/windows/desktop/ms684225.aspx
type MODULEENTRY32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  *uint8
	ModBaseSize  uint32
	HModule      HMODULE
	SzModule     [MAX_MODULE_NAME32 + 1]uint16
	SzExePath    [MAX_PATH]uint16
}

const (
	MAX_MODULE_NAME32 = 255
	MAX_PATH          = 260
)

func Module32First(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

func Module32Next(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

// ReadProcessMemory Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
func ReadProcessMemory(hProcess HANDLE, lpBaseAddress uint32, size uint) (data []byte, err error) {
	var numBytesRead uintptr
	data = make([]byte, size)

	ret, _, err := procReadProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))

	//Better error check with no lang problems (See Return value).
	if ret == 0 {
		return
	}

	err = nil
	return
}

// WriteProcessMemory Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
func WriteProcessMemory(hProcess HANDLE, lpBaseAddress uint32, data []byte, size uint) (err error) {
	var numBytesRead uintptr

	ret, _, err := procWriteProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))

	if ret == 0 {
		return
	}

	err = nil
	return
}
