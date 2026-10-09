//go:build windows

package processowner

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestLookupMatchesCompleteLoopbackTuple(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ln, e := net.Listen("tcp", address)
			if e != nil {
				t.Skip(e)
			}
			defer ln.Close()
			c, e := net.Dial("tcp", ln.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			a, e := ln.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			var ownerName string
			for attempt := 0; attempt < 10; attempt++ {
				owner := Lookup(a.RemoteAddr(), a.LocalAddr())
				if owner.Matched && owner.PID == uint32(os.Getpid()) && owner.Created != "" {
					ownerName = owner.Name
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if ownerName == "" {
				t.Fatal("failed to associate accepted socket with its actual client process")
			}
			wrong := *a.RemoteAddr().(*net.TCPAddr)
			wrong.Port = 0
			if Lookup(&wrong, a.LocalAddr()).Matched {
				t.Fatal("attributed an unrelated TCP tuple")
			}
		})
	}
}
