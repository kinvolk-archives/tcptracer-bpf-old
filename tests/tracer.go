package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

type EventType uint32

const (
	_ EventType = iota
	EventConnect
	EventAccept
	EventClose
)

func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	default:
		return "unknown"
	}
}

type tcpEventV4 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu   uint64
	Type  uint32
	Pid   uint32
	Comm  [16]byte
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	NetNS uint32
}

type tcpEventV6 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu    uint64
	Type   uint32
	Pid    uint32
	Comm   [16]byte
	SAddrH uint64
	SAddrL uint64
	DAddrH uint64
	DAddrL uint64
	SPort  uint16
	DPort  uint16
	NetNS  uint32
}

type tcpTracerState uint64

const (
	uninitialized tcpTracerState = iota
	checking
	checked
	ready
)

type guessWhat uint64

const (
	guessSaddr guessWhat = iota
	guessDaddr
	guessFamily
	guessSport
	guessDport
	guessNetns
	guessDaddrIPv6
)

type tcpTracerStatus struct {
	status          tcpTracerState
	pidTgid         uint64
	what            guessWhat
	offsetSaddr     uint64
	offsetDaddr     uint64
	offsetSport     uint64
	offsetDport     uint64
	offsetNetns     uint64
	offsetIno       uint64
	offsetFamily    uint64
	offsetDaddrIPv6 uint64
	err             byte
	saddr           uint32
	daddr           uint32
	sport           uint16
	dport           uint16
	netns           uint32
	family          uint16
	daddrIPv6       [4]uint32
}

var byteOrder binary.ByteOrder

// In lack of binary.HostEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}
}

func listen(url, netType string, finish chan struct{}) {
	l, err := net.Listen(netType, url)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	select {
	case <-finish:
		l.Close()
		return
	}
}

func compareIPv6(a, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ownNetNS() (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &s); err != nil {
		return 0, err
	}
	return s.Ino, nil
}

func ipFromUint32Arr(ipv6Addr [4]uint32) net.IP {
	buf := make([]byte, 16)
	for i := 0; i < 16; i++ {
		buf[i] = *(*byte)(unsafe.Pointer((uintptr(unsafe.Pointer(&ipv6Addr[0])) + uintptr(i))))
	}
	return net.IP(buf)
}

func htons(a uint16) uint16 {
	arr := make([]byte, 2)
	binary.BigEndian.PutUint16(arr, a)
	return byteOrder.Uint16(arr)
}

func guessOffsets(b *elf.Module) error {
	listenIP := "127.0.0.2"
	listenPort := uint16(9091)
	bindAddress := fmt.Sprintf("%s:%d", listenIP, listenPort)

	finish := make(chan struct{})
	go listen(bindAddress, "tcp4", finish)
	time.Sleep(300 * time.Millisecond)

	currentNetns, err := ownNetNS()
	if err != nil {
		return fmt.Errorf("error getting current netns: %v", err)
		os.Exit(1)
	}

	mp := b.Map("tcptracer_status")

	var zero uint64
	pidTgid := uint64(os.Getpid()<<32 | syscall.Gettid())

	status := tcpTracerStatus{
		status:  checking,
		pidTgid: pidTgid,
	}

	err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status), 0)
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	dport := htons(listenPort)

	// 127.0.0.1
	saddr := 0x0100007F
	// 127.0.0.2
	daddr := 0x0200007F
	// will be set later
	sport := 0
	netns := uint32(currentNetns)
	family := syscall.AF_INET

	for status.status != ready {
		var daddrIPv6 [4]uint32

		daddrIPv6[0] = rand.Uint32()
		daddrIPv6[1] = rand.Uint32()
		daddrIPv6[2] = rand.Uint32()
		daddrIPv6[3] = rand.Uint32()

		ip := ipFromUint32Arr(daddrIPv6)

		if status.what != guessDaddrIPv6 {
			conn, err := net.Dial("tcp4", bindAddress)
			if err != nil {
				fmt.Printf("error: %v\n", err)
			}

			sport, err = strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}

			sport = int(htons(uint16(sport)))

			// set SO_LINGER to 0 so the connection state after closing is
			// CLOSE instead of TIME_WAIT. In this way, they will disappear
			// from the conntrack table after around 10 seconds instead of 2
			// minutes
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			} else {
				panic("not a tcp connection")
			}

			conn.Close()
		} else {
			conn, err := net.Dial("tcp6", fmt.Sprintf("[%s]:9092", ip))
			if err == nil {
				conn.Close()
			}
		}

		err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.status == checked {
			switch status.what {
			case guessSaddr:
				if status.saddr == uint32(saddr) {
					status.what++
					status.status = checking
				} else {
					status.offsetSaddr++
					status.status = checking
					status.saddr = uint32(saddr)
				}
			case guessDaddr:
				if status.daddr == uint32(daddr) {
					status.what++
					status.status = checking
				} else {
					status.offsetDaddr++
					status.status = checking
					status.daddr = uint32(daddr)
				}
			case guessFamily:
				if status.family == uint16(family) {
					status.what++
					status.status = checking
					// we know the sport ((struct inet_sock)->inet_sport) is
					// after the family field, so we start from there
					status.offsetSport = status.offsetFamily
				} else {
					status.offsetFamily++
					status.status = checking
				}
			case guessSport:
				if status.sport == uint16(sport) {
					status.what++
					status.status = checking
				} else {
					status.offsetSport++
					status.status = checking
				}
			case guessDport:
				if status.dport == dport {
					status.what++
					status.status = checking
				} else {
					status.offsetDport++
					status.status = checking
				}
			case guessNetns:
				if status.netns == netns {
					status.what++
					status.status = checking
				} else {
					status.offsetIno++
					// go to the next offsetNetns if we get an error
					if status.err != 0 || status.offsetIno >= 200 {
						status.offsetIno = 0
						status.offsetNetns++
					}
					status.status = checking
				}
			case guessDaddrIPv6:
				if compareIPv6(status.daddrIPv6, daddrIPv6) {
					status.what++
					status.status = ready
				} else {
					status.offsetDaddrIPv6++
					status.status = checking
				}
			default:
				return fmt.Errorf("Uh, oh!")
			}
		}

		err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status), 0)
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.offsetSaddr >= 200 || status.offsetDaddr >= 200 ||
			status.offsetSport >= 2000 || status.offsetDport >= 200 ||
			status.offsetNetns >= 200 || status.offsetFamily >= 200 ||
			status.offsetDaddrIPv6 >= 200 {
			fmt.Fprintf(os.Stderr, "overflow, bailing out!\n")
			os.Exit(1)
		}
	}

	close(finish)

	return nil
}

var lastTimestampV4 uint64
var lastTimestampV6 uint64

func tcpEventCbV4(event tcpEventV4) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff
	comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(event.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(event.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV4 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV4 = timestamp
}

func tcpEventCbV6(event tcpEventV6) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff
	comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, event.SAddrH)
	binary.LittleEndian.PutUint64(saddrbuf[8:], event.SAddrL)
	binary.LittleEndian.PutUint64(daddrbuf, event.DAddrH)
	binary.LittleEndian.PutUint64(daddrbuf[8:], event.DAddrL)

	sIP := net.IP(saddrbuf)
	dIP := net.IP(daddrbuf)

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %s %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV6 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV6 = timestamp
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s .../ebpf.o\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]

	b := elf.NewModule(fileName)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	err = b.EnableKprobes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	channelV4 := make(chan []byte)
	channelV6 := make(chan []byte)

	perfMapIPV4, err := elf.InitPerfMap(b, "tcp_event_ipv4", channelV4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	perfMapIPV6, err := elf.InitPerfMap(b, "tcp_event_ipv6", channelV6)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	if err := guessOffsets(b); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event tcpEventV4
		for {
			data := <-channelV4
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV4(event)
		}
	}()

	go func() {
		var event tcpEventV6
		for {
			data := <-channelV6
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV6(event)
		}
	}()

	perfMapIPV4.PollStart()
	perfMapIPV6.PollStart()
	<-sig
	perfMapIPV4.PollStop()
	perfMapIPV6.PollStop()
}
