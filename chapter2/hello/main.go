package main

import (
	"learning-ebpf-go/internal/filescanner"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func syscallName(base string) string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_sys_" + base
	case "arm64":
		return "__arm64_sys_" + base
	default:
		return "sys_" + base
	}
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	go filescanner.FileScan("/sys/kernel/debug/tracing/trace_pipe")

	var objs helloObjects
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	event := syscallName("execve")

	kp, err := link.Kprobe(event, objs.Hello, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	log.Printf("attached kprobe to %s", event)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("detaching and exiting")
}
