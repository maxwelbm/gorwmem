package gorwmem

import (
	"errors"
	"fmt"
	"unsafe"
)

// ProcessException Exception type of ProcessHandler.
type ProcessException error

// Process Type of simple process.
type Process struct {
	Name string
	Pid  uint32
}

// processHandler This type handles the process.
type processHandler struct {
	process  *Process
	hProcess uintptr
}

// ProcessHandler
// Constructor of ProcessHandler
// Param   (processName)	 : The name of process to handle.
// Returns (*processHandler) : A processHandler object.
// Errors  (err)		     : Error if you don't exist process with passed name.
func ProcessHandler(processName string) (hProcess *processHandler, err ProcessException) {
	_hProcess := processHandler{}
	_hProcess.process, err = processFromName(processName)

	return &_hProcess, err
}

// list This function returns a list of process.
func list() (processes []*Process) {
	processes = make([]*Process, 0)

	handle := CreateToolhelp32Snapshot(Th32csSnapprocess, 0)
	if handle == 0 {
		fmt.Printf("Warning, CreateToolhelp32Snapshot failed. Error: ")
		return
	}

	var pEntry PROCESSENTRY32
	Processentry32Size := unsafe.Sizeof(pEntry)
	pEntry.Size = uint32(Processentry32Size)

	_err := Process32First(handle, &pEntry) //Read frist element.
	if _err == nil {
		for {
			name := UTF16PtrToString(&pEntry.ExeFile[0])
			processes = append(processes, &Process{name, pEntry.ProcessID})
			_err = Process32Next(handle, &pEntry)
			if _err != nil {
				break
			}
		} //Loops until reach last process.
	} else {
		fmt.Printf("Warning, Process32First failed. Error: %v", _err)
	}

	CloseHandle(handle)

	return
}

// processFromName This function search a process with passed name in list() and returns it.
func processFromName(processName string) (*Process, ProcessException) {
	for _, process := range list() {
		if process.Name == processName {
			return process, nil
		}
	}

	err := errors.New("invalid process name")
	return nil, err
}

// Open
// the process of ProcessHandler in get self debug privileges.
// Public function of (process_handler) package.
// Errors (err): Error if you don't exist process or cannot open with PAA.
func (ph *processHandler) Open() (err ProcessException) {

	if ph.process == nil {
		err = errors.New("the selected process does not exist")
		return
	}

	setDebugPrivilege()

	handle, _err := OpenProcess(PROCESS_ALL_ACCESS, false, ph.process.Pid)
	if _err != nil {
		err = errors.New("Cannot open this process. Reason: " + _err.Error())
		return
	}

	ph.hProcess = uintptr(handle)
	return
}

// setDebugPrivilege This function try to set self process with debug privileges.
func setDebugPrivilege() bool {
	pseudoHandle, _err := GetCurrentProcess()
	if _err != nil {
		fmt.Printf("Warning, GetCurrentProcess failed. Error: %v", _err)
		return false
	}

	hToken := HANDLE(0)
	if !OpenProcessToken(HANDLE(pseudoHandle), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken) {
		fmt.Printf("Warning, GetCurrentProcess failed.")
		return false
	}

	return setPrivilege(hToken, SE_DEBUG_NAME, true)
}

// setPrivilege This function try to set privileges to a process.
func setPrivilege(hToken HANDLE, lpszPrivilege string, bEnablePrivilege bool) bool {
	tPrivs := TOKEN_PRIVILEGES{}
	TokenPrivilegesSize := uint32(unsafe.Sizeof(tPrivs))
	luid := LUID{}

	if !LookupPrivilegeValue(string(""), lpszPrivilege, &luid) {
		fmt.Printf("Warning, LookupPrivilegeValue failed.")
		return false
	}

	tPrivs.PrivilegeCount = 1
	tPrivs.Privileges[0].Luid = luid

	if bEnablePrivilege {
		tPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	} else {
		tPrivs.Privileges[0].Attributes = 0
	}

	if !AdjustTokenPrivileges(hToken, 0, &tPrivs, TokenPrivilegesSize, nil, nil) {
		fmt.Printf("Warning, AdjustTokenPrivileges failed.")
		return false
	}

	return true
}

// GetModuleFromName This function search a module inside process.
func (ph *processHandler) GetModuleFromName(module string) (uintptr, error) {
	var (
		me32 MODULEENTRY32
		snap HANDLE
	)

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, ph.process.Pid)
	me32.Size = uint32(unsafe.Sizeof(me32))

	for ok := Module32First(snap, &me32); ok; ok = Module32Next(snap, &me32) {
		szModule := UTF16PtrToString(&me32.SzModule[0])

		if szModule == module {
			return (uintptr)(unsafe.Pointer(me32.ModBaseAddr)), nil
		}
	}

	return (uintptr)(unsafe.Pointer(me32.ModBaseAddr)), errors.New("module not found")
}

// ReadBytes
// Low level facade to Read memory.
// Public function of (process_handler) package.
// Param   (address): The process memory address in hexadecimal. EX: (0X0057F0F0).
// Param   (size)   : The size of bytes that we want to read.
// Returns (data)   : A byte array with data.
// Errors  (err)	: This will be not nil if handle is not opened or cannot read the memory.
func (ph *processHandler) ReadBytes(address uint, size uint) (data []byte, err ProcessException) {
	if ph.hProcess == 0 {
		err = errors.New("no process handle")
	}

	data, _err := ReadProcessMemory(HANDLE(ph.hProcess), uint32(address), size)
	if _err != nil {
		err = errors.New("Error reading memory. Reason: " + _err.Error())
	}

	return
}

// WriteBytes
// Low level facade to Write memory.
// Public function of (process_handler) package.
// Param   (address) : The process memory address in hexadecimal. EX: (0X0057F0F0).
// Param   (data)    : A byte array with data.
// Errors  (err)	 : This will be not nil if handle is not opened or cannot write the memory.
func (ph *processHandler) WriteBytes(address uint, data []byte) (err ProcessException) {
	if ph.hProcess == 0 {
		err = errors.New("no process handle")
	}

	_err := WriteProcessMemory(HANDLE(ph.hProcess), uint32(address), data, uint(len(data)))
	if _err != nil {
		err = errors.New("Error writing memory. Reason: " + _err.Error())
	}

	return
}
