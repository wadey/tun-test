package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

var (
	flagName     = flag.String("name", "tun1", "tun device name")
	flagRoutines = flag.Int("routines", 1, "number of goroutines reading from tun")
	flagMTU      = flag.Int("mtu", 64*1024, "mtu")
	flagTSO      = flag.Bool("tso", false, "use TSO (IFF_VNET_HDR | TUNSETOFFLOAD)")
	flagMethod   = flag.String("method", "syscall", "method to use: stdlib, syscall")
)

const (
	IFF_TUN         = 0x0001
	IFF_TAP         = 0x0002
	IFF_NAPI        = 0x0010
	IFF_NO_PI       = 0x1000
	IFF_VNET_HDR    = 0x4000
	IFF_MULTI_QUEUE = 0x0100

	TUN_F_CSUM    = 0x01 /* You can hand me unchecksummed packets. */
	TUN_F_TSO4    = 0x02 /* I can handle TSO for IPv4 packets */
	TUN_F_TSO6    = 0x04 /* I can handle TSO for IPv6 packets */
	TUN_F_TSO_ECN = 0x08 /* I can handle TSO with ECN bits. */
	TUN_F_UFO     = 0x10 /* I can handle UFO packets */
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
	req.Flags = IFF_NO_PI | IFF_TUN | IFF_NAPI
	if *flagTSO {
		req.Flags |= IFF_VNET_HDR
	}
	copy(req.Name[:], *flagName)

	err = ioctl(uintptr(fdInt), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		panic(err)
	}

	if *flagTSO {
		err = ioctl(uintptr(fdInt), unix.TUNSETOFFLOAD, uintptr(TUN_F_CSUM|TUN_F_TSO4))
		if err != nil {
			panic(err)
		}
	}

	f := os.NewFile(uintptr(fdInt), "tun")

	var handle func(*os.File)
	switch *flagMethod {
	case "stdlib":
		handle = stdlibHandle
	case "syscall":
		if *flagTSO {
			handle = syscallTSOHandle
		} else {
			handle = syscallHandle
		}
	default:
		log.Fatal("invalid method")
	}

	for i := 0; i < *flagRoutines-1; i++ {
		go handle(f)
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

		orig := packet

		if packet[0]&0xF0 == 0x40 {
			swapIP(packet, swap)
			if packet[10] == 0 && packet[11] == 0 {
				log.Print("zero checksum ", hex.EncodeToString(packet[:n]))
				binary.BigEndian.PutUint16(packet[10:], ipChecksum(packet[0:20]))
			}
		} else {
			log.Print("not ipv4 ", hex.EncodeToString(packet[:n]))
			continue
		}

		x, err := unix.Write(fdInt, orig[:n])
		if err != nil {
			panic(err)
		}
		if n != x {
			panic(fmt.Errorf("partial write: %d of %d", x, n))
		}
	}
}

func syscallTSOHandle(f *os.File) {
	runtime.LockOSThread()
	full := make([]byte, 64*1024)
	swap := make([]byte, 4)
	fdInt := int(f.Fd())

	vnetHdr := virtioNetHdr{}

	for {
		n, err := unix.Read(fdInt, full)
		if err != nil {
			panic(err)
		}

		vnetHdr.flags = full[0]
		vnetHdr.gsoType = full[1]

		// 2021/02/05 11:57:52 vnet hdr: 2958: main.virtioNetHdr{flags:0x1, gsoType:0x1, hdrLen:0x34, gsoSize:0x5a8, csumStart:0x14, csumOffset:0x10}:
		// 01013400a80514001000
		// 45000b847d27400040065a0bac1f0001ac1f0002b1c414516f759e43a115
		vnetHdr.hdrLen = binary.LittleEndian.Uint16(full[2:])
		vnetHdr.gsoSize = binary.LittleEndian.Uint16(full[4:])
		vnetHdr.csumStart = binary.LittleEndian.Uint16(full[6:])
		vnetHdr.csumOffset = binary.LittleEndian.Uint16(full[8:])

		if vnetHdr.gsoType == VIRTIO_NET_HDR_GSO_NONE {
			// Just send it!

			syscallHandleOne(fdInt, full[:n], full[10:n], swap)
		} else {
			full[0] = 0
			full[1] = 0
			// log.Printf("vnet hdr: %d: %#v: %s", n, vnetHdr, hex.EncodeToString(full[:10]))
			// log.Printf("vnet gso hdr: %s", hex.EncodeToString(full[10:vnetHdr.hdrLen]))
			i := 0
			sz := vnetHdr.hdrLen + vnetHdr.gsoSize
			packet := full[10 : 10+sz]
			rem := full[10+vnetHdr.hdrLen : n]
			for len(rem) > 0 {
				// log.Printf("vnet gso %d: %d: %s", i, len(packet), hex.EncodeToString(packet))

				if i > 0 {
					// Copy the data to be next to the vnetHdr, so we can send it
					copy(packet[vnetHdr.hdrLen:], rem[:vnetHdr.gsoSize])
				}

				pp := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
				pp.Layer(layers.LayerTypeTCP).(*layers.TCP).SetNetworkLayerForChecksum(
					pp.NetworkLayer())
				// log.Print(pp)
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{ComputeChecksums: true}
				err := gopacket.SerializePacket(buf, opts, pp)
				if err != nil {
					panic(err)
				}
				copy(full[10:], buf.Bytes())

				// Debug:
				pp = gopacket.NewPacket(full[10:10+sz], layers.LayerTypeIPv4, gopacket.Default)
				log.Print(pp.Dump())

				// TODO fix TCP CSUM?
				syscallHandleOne(fdInt, full[:10+sz], packet, swap)

				rem = rem[vnetHdr.gsoSize:]
				i++
			}
		}
	}
}

func syscallHandleOne(fdInt int, full, packet, swap []byte) {
	if packet[0]&0xF0 == 0x40 {
		swapIP(packet, swap)
		if packet[10] == 0 && packet[11] == 0 {
			log.Print("zero checksum ", hex.EncodeToString(packet))
			binary.BigEndian.PutUint16(packet[10:], ipChecksum(packet[0:20]))
		}
	} else {
		log.Print("not ipv4 ", hex.EncodeToString(packet))
		return
	}

	x, err := unix.Write(fdInt, full)
	if err != nil {
		panic(err)
	}
	if len(full) != x {
		panic(fmt.Errorf("partial write: %d of %d", x, len(full)))
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

func ipChecksum(b []byte) uint16 {
	var c uint32
	sz := len(b) - 1

	for i := 0; i < sz; i += 2 {
		c += uint32(b[i]) << 8
		c += uint32(b[i+1])
	}
	if sz%2 == 0 {
		c += uint32(b[sz]) << 8
	}

	for (c >> 16) > 0 {
		c = (c & 0xffff) + (c >> 16)
	}

	return ^uint16(c)
}

// computeChecksum computes a TCP or UDP checksum.  headerAndPayload is the
// serialized TCP or UDP header plus its payload, with the checksum zero'd
// out. headerProtocol is the IP protocol number of the upper-layer header.
// func computeChecksum(headerAndPayload []byte, headerProtocol uint32) (uint16, error) {
// 	if c.pseudoheader == nil {
// 		return 0, errors.New("TCP/IP layer 4 checksum cannot be computed without network layer... call SetNetworkLayerForChecksum to set which layer to use")
// 	}
// 	length := uint32(len(headerAndPayload))
// 	csum, err := c.pseudoheader.pseudoheaderChecksum()
// 	if err != nil {
// 		return 0, err
// 	}
// 	csum += headerProtocol
// 	csum += length & 0xffff
// 	csum += length >> 16
// 	return tcpipChecksum(headerAndPayload, csum), nil
// }

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}
