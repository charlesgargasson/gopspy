package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

var helpmsg string = `
 Usage:

    -env
        Retrieve env values

    -help
        Print help

    -debug 
        Debug info

`

var version string = `
  ▗▄▄▖ ▗▄▖ ▗▄▄▖  ▗▄▄▖▗▄▄▖▗▖  ▗▖
 ▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌ ▐▌▝▚▞▘ 
 ▐▌▝▜▌▐▌ ▐▌▐▛▀▘  ▝▀▚▖▐▛▀▘  ▐▌  
 ▝▚▄▞▘▝▚▄▞▘▐▌   ▗▄▄▞▘▐▌    ▐▌  

                version 1.3.0

`

var debug bool = false
var x []string = []string{"o", "y", "a", "e", "i", "u"}
var interval1 int = 10 // ms, Interval for pid listing
var interval2 int = 10 // ms, Interval for full process reload (not auto)
var lastrefresh time.Time
var getenv bool

type processInfoStruct struct {
	handle     windows.Handle
	token      windows.Token
	infoLevel  int
	pid        uint32
	path       string
	exe        string
	cmdLine    string
	workDir    string
	user       string
	elevated   bool
	restricted bool
	integrity  string
	session    uint32
	tree       string
	privilege  map[string]bool
	env        map[string]string
	mu         sync.Mutex
}

func displayProcess(p *processInfoStruct) {
	var s string
	s += fmt.Sprintf(strings.Repeat("-", 50) + " " + timeFormat(time.Now()) + " " + strings.Repeat("-", 50) + "\n\n")

	s += fmt.Sprintf("PID: %d\n", p.pid)

	if debug {
		s += fmt.Sprintf("INFOLEVEL: %d\n", p.infoLevel)
	}

	if p.exe != "" {
		s += fmt.Sprintf("EXE: %s\n", p.exe)
	}

	if p.cmdLine != "" {
		s += fmt.Sprintf("CMD: %s\n", p.cmdLine)
	} else {
		if p.path != "" {
			s += fmt.Sprintf("PATH: %s\n", p.path)
		}
	}

	if p.workDir != "" {
		s += fmt.Sprintf("DIR: %s\n", p.workDir)
	}

	if p.infoLevel > 0 {
		s += fmt.Sprintf("ELEVATED (UAC): %t\n", p.elevated)
		s += fmt.Sprintf("RESTRICTED: %t\n", p.restricted)
	}

	if p.integrity != "" {
		s += fmt.Sprintf("INTEGRITY: %s\n", p.integrity)
	}

	if p.user != "" {
		s += fmt.Sprintf("USER: %s\n", p.user)
	}

	if p.session != uint32(9999) {
		s += fmt.Sprintf("SESSION: %d\n", p.session)
	}

	if len(p.env) > 0 && getenv {
		s += fmt.Sprintf("ENV:\n")
		for key, value := range p.env {
			s += fmt.Sprintf("- %s: %s\n", key, value)
		}
	}

	if len(p.privilege) > 0 {
		s += fmt.Sprintf("PRIVILEGES:\n")
		for priv, status := range p.privilege {
			s += fmt.Sprintf("- %s: %t\n", priv, status)
		}
	}

	if p.tree != "" {
		s += fmt.Sprintf("PTREE: %s\n", p.tree)
	}

	fmt.Print(s + "\n")
}

func handleNewPid(pid uint32) {
	var p processInfoStruct
	p.pid = pid

	defer displayProcess(&p)

	var wg sync.WaitGroup
	wg.Wait()

	//////////////////////////////////////////////////////////////////////////////////////
	// Retrieving informations based on PID

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := getExecutable(pid)
		p.mu.Lock()
		p.exe = result
		p.mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := resolveProcessChain(pid)
		p.mu.Lock()
		p.tree = result
		p.mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var session uint32
		err := windows.ProcessIdToSessionId(pid, &session)
		if err != nil {
			session = 9999
		}
		p.mu.Lock()
		p.session = session
		p.mu.Unlock()
	}()

	//////////////////////////////////////////////////////////////////////////////////////
	// Retrieving informations based on handle

	infoLevel, handle, err := getHandle(pid)
	if err != nil {
		wg.Wait()
		return
	}
	defer func() {
		go windows.CloseHandle(handle)
	}()

	p.mu.Lock()
	p.infoLevel = infoLevel
	p.handle = handle
	p.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := getExecutablePath(handle)
		p.mu.Lock()
		p.path = result
		p.mu.Unlock()
	}()

	if infoLevel >= 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmdLine, workDir, env, err := getProcessMemoryInfos(handle)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.cmdLine = cmdLine
			p.workDir = workDir
			p.env = env
			p.mu.Unlock()
		}()
	}

	//////////////////////////////////////////////////////////////////////////////////////
	// Retrieving informations based on token

	if infoLevel < 2 {
		wg.Wait()
		return
	}

	token, err := getToken(handle)
	if err != nil {
		wg.Wait()
		return
	}
	defer func() {
		go token.Close()
	}()

	p.mu.Lock()
	p.token = token
	p.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := getProcessOwner(token)
		p.mu.Lock()
		p.user = result
		p.mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result := token.IsElevated()
		p.mu.Lock()
		p.elevated = result
		p.mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := getIntegrityLevel(token)
		p.mu.Lock()
		p.integrity = result
		p.mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ := getAccessRights(token)
		p.mu.Lock()
		p.privilege = result
		p.mu.Unlock()
	}()

	wg.Wait()
}

func main() {
	fmt.Printf("%s", version)
	defer fmt.Printf("\n")

	var usage string

	flag.BoolVar(&debug, "debug", false, usage)

	var help bool
	flag.BoolVar(&help, "help", false, usage)
	flag.BoolVar(&help, "h", false, usage)

	var checkpid int
	flag.IntVar(&checkpid, "pid", 0, usage)

	flag.BoolVar(&getenv, "env", false, usage)

	flag.Parse()

	if help {
		fmt.Printf(helpmsg)
		return
	}

	if checkpid > 0 {
		handleNewPid(uint32(checkpid))
		return
	}

	var oldpids []uint32
	refreshProcessList()
	for {
		pids := getPids()
		for _, pid := range pids {
			if pid == uint32(0) {
				continue
			}
			if !slices.Contains(oldpids, pid) {
				go handleNewPid(pid)
			}
		}
		oldpids = pids
		time.Sleep(time.Duration(interval1) * time.Millisecond)
	}
}
