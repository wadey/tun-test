package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	flagName     = flag.String("name", "tun1", "tun device name")
	flagRoutines = flag.Int("routines", 1, "number of goroutines reading from tun")
	flagMTU      = flag.Int("mtu", 1500, "mtu")
	flagMethod   = flag.String("method", "syscall", "method to use: stdlib, syscall")
)

const (
	IFFTUN        = 0x0001
	IFFTAP        = 0x0002
	IFFNOPI       = 0x1000
	IFFMULTIQUEUE = 0x0100
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

func main() {
	flag.Parse()

	var fdInt int
	var err error
	if fdInt, err = unix.Open(
		"/dev/net/tun", os.O_RDWR, 0); err != nil {
		panic(err)
	}

	var req ifReq
	req.Flags = IFFNOPI | IFFTUN
	if *flagRoutines > 1 {
		req.Flags |= IFFMULTIQUEUE
	}
	copy(req.Name[:], *flagName)

	err = ioctl(uintptr(fdInt), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		panic(err)
	}

	f := os.NewFile(uintptr(fdInt), "tun")

	var handle func(*os.File)
	switch *flagMethod {
	case "stdlib":
		handle = stdlibHandle
	case "syscall":
		handle = syscallHandle
	default:
		log.Fatal("invalid method")
	}

	for i := 0; i < *flagRoutines-1; i++ {
		// MULTIQUEUE
		var fdInt2 int

		if fdInt2, err = unix.Open(
			"/dev/net/tun", os.O_RDWR, 0); err != nil {
			panic(err)
		}

		req.Flags = IFFNOPI | IFFTUN | IFFMULTIQUEUE
		copy(req.Name[:], *flagName)

		err = ioctl(uintptr(fdInt2), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
		if err != nil {
			panic(err)
		}
		f2 := os.NewFile(uintptr(fdInt2), "tun")

		go handle(f2)
	}
	handle(f)
}

func stdlibHandle(f *os.File) {
	runtime.LockOSThread()
	packet := make([]byte, *flagMTU)
	swap := make([]byte, 4)

	for {
		n, err := f.Read(packet)
		if err != nil {
			panic(err)
		}

		swapIP(packet, swap)

		x, err := f.Write(packet[:n])
		if err != nil {
			panic(err)
		}
		if n != x {
			panic(fmt.Errorf("partial write: %d of %d", x, n))
		}
	}
}

func syscallHandle(f *os.File) {
	runtime.LockOSThread()
	packet := make([]byte, *flagMTU)
	swap := make([]byte, 4)
	fdInt := int(f.Fd())

	for {
		n, err := unix.Read(fdInt, packet)
		if err != nil {
			panic(err)
		}

		swapIP(packet, swap)

		x, err := unix.Write(fdInt, packet[:n])
		if err != nil {
			panic(err)
		}
		if n != x {
			panic(fmt.Errorf("partial write: %d of %d", x, n))
		}
	}
}

// Swap dest / src IPs
// (don't need to recalculate checksum since we are just reordering values)
func swapIP(packet, swap []byte) {
	ipv4 := packet[0:20]
	copy(swap, ipv4[12:16])
	copy(ipv4[12:16], ipv4[16:20])
	copy(ipv4[16:20], swap)
}

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}
