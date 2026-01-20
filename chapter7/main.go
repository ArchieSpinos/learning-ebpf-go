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

	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(sysutils.SyscallName("execve"), objs.KprobeSysExecve, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	kp1, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TpSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer kp1.Close()

	kp2, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TpBtfExec,
	})
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer kp2.Close()

	kp3, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exec",
		Program: objs.RawTpExec,
	})
	if err != nil {
		log.Fatalf("attach raw tracepoint: %v", err)
	}
	defer kp3.Close()

	reader, err := perf.NewReader(objs.Output, 1024)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	type eventData struct {
		Pid     int32
		Uid     int32
		Command [16]byte
		Message [12]byte
		Path    [16]byte
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
			"%-6d %-6d %-16s %-16s %s\n",
			ev.Pid,
			ev.Uid,
			bytes.TrimRight(ev.Command[:], "\x00"),
			bytes.TrimRight(ev.Path[:], "\x00"),
			bytes.TrimRight(ev.Message[:], "\x00"),
		)
	}
}
