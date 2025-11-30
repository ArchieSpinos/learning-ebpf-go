package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"learning-ebpf-go/internal/sysutils"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs hello_bufferObjects
	if err := loadHello_bufferObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	event := sysutils.SyscallName("execve")

	kp, err := link.Kprobe(event, objs.Hello, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	reader, err := perf.NewReader(objs.Events, 1024)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	type eventData struct {
		Pid     uint32
		Uid     uint32
		Command [16]byte
		Message [12]byte
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Fatal(err)
		}

		var ev eventData
		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&ev,
		)
		if err != nil {
			log.Printf("failed to parse perf event: %v", err)
			continue
		}

		fmt.Printf(
			"%-16s %-6d %-6d %s\n",
			bytes.TrimRight(ev.Command[:], "\x00"),
			ev.Pid,
			ev.Uid,
			ev.Message,
		)
	}

}
