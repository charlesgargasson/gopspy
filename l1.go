package main

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var processMu sync.RWMutex
var processList map[uint32]string
var processParentList map[uint32]uint32

// Retrieve the executable path of the process
func getExecutablePath(h windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buffer))
	err := windows.QueryFullProcessImageName(h, 0, &buffer[0], &size)
	if err != nil {
		return "", fmt.Errorf("failed to get process executable path: %v", err)
	}
	return windows.UTF16ToString(buffer), nil
}

// Open token from process
func getToken(h windows.Handle) (windows.Token, error) {
	var t windows.Token
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &t)
	if err != nil {
		return t, err
	}
	return t, nil
}

// Enum pids with EnumProcesses
func getPids() []uint32 {
	pids := make([]uint32, 1024)
	var bytesReturned uint32
	err := windows.EnumProcesses(pids, &bytesReturned)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	return pids
}

// Read infos from process memory
func getProcessMemoryInfos(h windows.Handle) (string, string, map[string]string, error) {
	// Define return vars
	var cmdLine string
	var currentDirectory string
	envVars := make(map[string]string)

	var info windows.PROCESS_BASIC_INFORMATION
	err := windows.NtQueryInformationProcess(
		h,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
		nil,
	)
	if err != nil {
		return cmdLine, currentDirectory, envVars, err
	}

	var peb windows.PEB
	err = windows.ReadProcessMemory(
		h,
		uintptr(unsafe.Pointer(info.PebBaseAddress)),
		(*byte)(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb),
		nil,
	)
	if err != nil {
		return cmdLine, currentDirectory, envVars, err
	}

	var params windows.RTL_USER_PROCESS_PARAMETERS
	err = windows.ReadProcessMemory(
		h,
		uintptr(unsafe.Pointer(peb.ProcessParameters)),
		(*byte)(unsafe.Pointer(&params)),
		unsafe.Sizeof(params),
		nil,
	)
	if err != nil {
		return cmdLine, currentDirectory, envVars, err
	}

	var wg sync.WaitGroup
	wg.Add(3)

	////////////////////////////////////////
	// CMDLINE
	go func() {
		defer wg.Done()
		var cmdLinebuffer []uint16 = make([]uint16, params.CommandLine.Length)
		err = windows.ReadProcessMemory(
			h,
			uintptr(unsafe.Pointer(params.CommandLine.Buffer)),
			(*byte)(unsafe.Pointer(&cmdLinebuffer[0])),
			uintptr(params.CommandLine.Length),
			nil,
		)
		if err != nil {
			return
		}
		cmdLine = windows.UTF16ToString(cmdLinebuffer[:])
	}()

	////////////////////////////////////////
	// WORKDIR
	go func() {
		defer wg.Done()
		var currentDirectorybuffer []uint16 = make([]uint16, params.CurrentDirectory.DosPath.Length)
		err = windows.ReadProcessMemory(
			h,
			uintptr(unsafe.Pointer(params.CurrentDirectory.DosPath.Buffer)),
			(*byte)(unsafe.Pointer(&currentDirectorybuffer[0])),
			uintptr(params.CurrentDirectory.DosPath.Length),
			nil,
		)
		if err != nil {
			return
		}
		currentDirectory = windows.UTF16ToString(currentDirectorybuffer[:])
	}()

	////////////////////////////////////////
	// ENV
	go func() {
		defer wg.Done()
		if getenv {
			// Read the environment block
			var envBlock []uint16 = make([]uint16, params.EnvironmentSize/2)
			err = windows.ReadProcessMemory(
				h,
				uintptr(params.Environment),
				(*byte)(unsafe.Pointer(&envBlock[0])),
				params.EnvironmentSize,
				nil,
			)
			if err != nil {
				return
			}

			// Now, let's manually process the UTF-16 environment block
			start := 0

			// Iterate through the environment block looking for null-terminated strings
			for i := 0; i < len(envBlock); i++ {
				// When we hit a null character (0x00), we've found the end of a string
				if envBlock[i] == 0 {
					// If there's a string between start and i, process it
					if start != i {
						envString := windows.UTF16ToString(envBlock[start:i])
						// Split the environment variable into key=value pairs
						parts := strings.SplitN(envString, "=", 2)
						if len(parts) == 2 {
							envVars[parts[0]] = parts[1]
						}
					}
					// Move to the next potential string (after the null terminator)
					start = i + 1
				}
			}
		}
	}()

	wg.Wait()
	return cmdLine, currentDirectory, envVars, nil
}

// Extract process owner from user token
func getProcessOwner(t windows.Token) (owner string, err error) {
	// Get the token user information (which contains the SID)
	tokenUser, err := t.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("failed to get token user: %v", err)
	}

	// Prepare to lookup the account name associated with the SID
	userSID := tokenUser.User.Sid

	// Buffer sizes for account and domain names
	var accountNameSize, domainNameSize uint32
	var accountType uint32

	// Perform an initial lookup to determine buffer sizes
	err = windows.LookupAccountSid(
		nil,
		userSID,
		nil,
		&accountNameSize,
		nil,
		&domainNameSize,
		&accountType,
	)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("failed to lookup account SID (1st call): %v", err)
	}

	// Allocate buffers based on the sizes determined
	accountName := make([]uint16, accountNameSize)
	domainName := make([]uint16, domainNameSize)

	// Perform the actual lookup to get the account and domain names
	err = windows.LookupAccountSid(
		nil,
		userSID,
		&accountName[0],
		&accountNameSize,
		&domainName[0],
		&domainNameSize,
		&accountType,
	)
	if err != nil {
		return "", fmt.Errorf("failed to lookup account SID (2nd call): %v", err)
	}

	// Convert the account name and domain name from UTF-16 to string
	account := windows.UTF16ToString(accountName)
	domain := windows.UTF16ToString(domainName)

	return fmt.Sprintf("%s\\%s", domain, account), nil
}

// Trying to open process with extended rights
func getHandle(pid uint32) (int, windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
		if err != nil {
			h, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if err != nil {
				return 0, h, err
			}
			return 1, h, nil
		}
		return 2, h, nil
	}
	return 3, h, nil
}

func getIntegrityLevel(t windows.Token) (string, error) {
	var tokenILLength uint32
	// First call to GetTokenInformation to get the required buffer size
	err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &tokenILLength)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("%v", err)
	}

	// Allocate the buffer for integrity level information
	ilBuffer := make([]byte, tokenILLength)

	// Call GetTokenInformation again to retrieve the integrity level information
	err = windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &ilBuffer[0], tokenILLength, &tokenILLength)
	if err != nil {
		return "", fmt.Errorf("%v", err)
	}

	// The structure returned is TOKEN_MANDATORY_LABEL
	// Use unsafe.Pointer to convert the buffer to the appropriate structure
	mandatoryLabel := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&ilBuffer[0]))
	sid := mandatoryLabel.Label.Sid

	// Retrieve the integrity level, which is stored in the first sub-authority of the SID
	il := sid.SubAuthority(0)

	// integrity levels
	U := uint32(0x00000000)
	L := uint32(0x00001000)
	M := uint32(0x00002000)
	H := uint32(0x00003000)
	S := uint32(0x00004000)
	P := uint32(0x00005000)

	// Interpret the integrity level based on the RID (Relative Identifier)
	switch {
	case il >= P:
		return "PROTECTED", nil
	case il >= S:
		return "SYSTEM", nil
	case il >= H:
		return "HIGH", nil
	case il >= M:
		return "MEDIUM", nil
	case il >= L:
		return "LOW", nil
	case il >= U:
		return "UNTRUSTED", nil
	default:
		return "???", nil
	}
}

func getAccessRights(hToken windows.Token) (map[string]bool, error) {
	var tokenPrivLength uint32
	// First call to GetTokenInformation to get the required buffer size
	err := windows.GetTokenInformation(hToken, windows.TokenPrivileges, nil, 0, &tokenPrivLength)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("%v", err)
	}

	// Allocate the buffer for privileges information
	privBuffer := make([]byte, tokenPrivLength)

	// Call GetTokenInformation again to retrieve the token privileges information
	err = windows.GetTokenInformation(hToken, windows.TokenPrivileges, &privBuffer[0], tokenPrivLength, &tokenPrivLength)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	// Cast the buffer to the TOKEN_PRIVILEGES structure
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&privBuffer[0]))

	// Create a map to store the privilege names
	privs := make(map[string]bool)

	// Loop through all privileges in the token
	// for i := uint32(0); i < tokenPrivileges.PrivilegeCount; i++ {
	ap := tp.AllPrivileges()
	for _, priv := range ap {
		// Get the LUID of the privilege
		luid := priv.Luid

		// Convert the LUID to a privilege name
		var nameLength uint32 = 256
		name := make([]uint16, nameLength)
		err = getName(nil, &luid, &name[0], &nameLength)
		if err != nil {
			return nil, fmt.Errorf("%v", err)
		}

		// Convert the privilege name from UTF-16 to a Go string
		privName := windows.UTF16ToString(name)

		// Get the attributes of the privilege (enabled, disabled, etc.)
		privAttr := priv.Attributes
		state := false
		if privAttr&windows.SE_PRIVILEGE_ENABLED != 0 {
			state = true
		}

		privs[privName] = state
	}

	return privs, nil
}

// Look Privilege Name with LookupPrivilegeNameW
func getName(systemName *uint16, luid *windows.LUID, name *uint16, size *uint32) error {
	xb := "L" + x[0] + "" + x[0] + "k" + x[5] + "pPr" + x[4] + "v" + x[4] + "l" + x[3] + "g" + x[3] + "N" + x[2] + "m" + x[3] + "W"
	xa := x[2] + "dv" + x[2] + "p" + x[4] + "32.dll"
	nls := windows.NewLazySystemDLL
	np := nls(xa).NewProc
	f := np(xb)
	r1, _, e1 := f.Call(
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(luid)),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(size)),
	)
	if r1 == 0 {
		return error(e1)
	}
	return nil
}

// NtQuerySystemInformation function call wrapper
func querySystemInformation() ([]byte, error) {
	var length uint32 = 1024 * 1024 // Start with a buffer of 1MB
	buffer := make([]byte, length)
	status := windows.NtQuerySystemInformation(
		windows.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		uint32(len(buffer)),
		&length,
	)

	if status != nil && status != windows.STATUS_INFO_LENGTH_MISMATCH {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %v", status)
	}

	if status == windows.STATUS_INFO_LENGTH_MISMATCH {
		// The buffer was too small, retry with the correct length
		buffer = make([]byte, length)
		status = windows.NtQuerySystemInformation(
			windows.SystemProcessInformation,
			unsafe.Pointer(&buffer[0]),
			uint32(len(buffer)),
			&length,
		)
		if status != nil {
			return nil, fmt.Errorf("NtQuerySystemInformation failed on retry: %v", status)
		}
	}

	return buffer, nil
}

// Get the list of processes including pids and binary name
func getProcessInfo() (map[uint32]string, map[uint32]uint32, error) {
	processList := make(map[uint32]string)
	processParentList := make(map[uint32]uint32)

	// Query system information
	buffer, err := querySystemInformation()
	if err != nil {
		return processList, processParentList, err
	}

	// Traverse through the list of SYSTEM_PROCESS_INFORMATION structures
	offset := uintptr(0)
	for {
		// Cast the buffer to a SYSTEM_PROCESS_INFORMATION structure
		spi := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		// Process ID
		pid := uint32(spi.UniqueProcessID)
		ppid := uint32(spi.InheritedFromUniqueProcessID)

		// Convert the process name from UNICODE_STRING
		processName := "<unknown>"
		if spi.ImageName.Length > 0 {
			processName = windows.UTF16PtrToString(spi.ImageName.Buffer)
		}

		// Print the process details
		//fmt.Printf("PID: %d, Executable Name: %s\n", pid, processName)
		processList[pid] = processName
		processParentList[pid] = ppid

		// Move to the next process
		if spi.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(spi.NextEntryOffset)
	}

	return processList, processParentList, nil
}

// Retrieve binary name from processList
func getExecutable(pid uint32) (string, error) {
	processMu.RLock()
	val, ok := processList[pid]
	processMu.RUnlock()
	if ok {
		return val, nil
	}
	refreshProcessList()
	processMu.RLock()
	val, ok = processList[pid]
	processMu.RUnlock()
	if ok {
		return val, nil
	}
	return "", fmt.Errorf("PID Not found in list")
}

// Retrieve the parent process tree
func resolveProcessChain(pid uint32) (string, error) {
	// Refresh process list if pid isn't present
	processMu.RLock()
	processParentListCopy := processParentList
	processListCopy := processList
	processMu.RUnlock()
	_, ok := processParentListCopy[pid]
	if !ok {
		refreshProcessList()
		processMu.RLock()
		processParentListCopy = processParentList
		processListCopy = processList
		processMu.RUnlock()
		_, ok = processParentList[pid]
		if !ok {
			return "", fmt.Errorf("PID Not found in list")
		}
	}

	var result string
	curpid := pid
	var safe int
	for {
		if safe > 20 {
			break
		}
		safe += 1
		ppid, ok := processParentListCopy[curpid]
		if ok {
			if ppid == uint32(0) {
				break
			}
			buff := ""
			buff += fmt.Sprintf("%d", ppid)
			exe, ok := processListCopy[ppid]
			if ok {
				buff += fmt.Sprintf(" %s", exe)
			}
			buff += fmt.Sprintf(" > ")
			result = buff + result
			curpid = ppid
		} else {
			break
		}
	}
	result += fmt.Sprintf("%d", pid)
	return result, nil
}

// Fresh process list
func refreshProcessList() {
	delta := time.Duration(interval2) * time.Millisecond
	if time.Since(lastrefresh) < delta {
		return
	}
	lastrefresh = time.Now()

	buffer1, buffer2, err := getProcessInfo()
	if err != nil {
		return
	} else {
		processMu.Lock()
		processList = buffer1
		processParentList = buffer2
		processMu.Unlock()
	}
}

func timeFormat(givenTime time.Time) string {
	return fmt.Sprintf(
		"%02d:%02d:%02d",
		givenTime.Hour(),
		givenTime.Minute(),
		givenTime.Second(),
	)
}
