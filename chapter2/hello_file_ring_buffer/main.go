package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs hello_file_ring_bufferObjects
	if err := loadHello_file_ring_bufferObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.CaptureOpenat, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	type eventData struct {
		Command  [16]byte
		Filename [256]byte
		Dfd      int32
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
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
			"File %d - %s opened by %s\n", ev.Dfd, bytes.TrimRight(ev.Filename[:], "\x00"),
			bytes.TrimRight(ev.Command[:], "\x00"),
		)
	}
}
