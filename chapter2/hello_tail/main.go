package main

import (
	"learning-ebpf-go/internal/filescanner"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	go filescanner.FileScan("/sys/kernel/debug/tracing/trace_pipe")

	var objs hello_tailObjects
	if err := loadHello_tailObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.hello_tailPrograms.Hello,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	ignoreFd := uint32(objs.hello_tailPrograms.IgnoreOpcode.FD())
	execFd := uint32(objs.hello_tailPrograms.HelloExec.FD())
	timerFd := uint32(objs.hello_tailPrograms.HelloTimer.FD())

	m := objs.hello_tailMaps.Syscall

	info, err := m.Info()
	if err != nil {
		log.Fatalf("getting map info: %v", err)
	}
	max := int(info.MaxEntries)

	//  Ignore all syscalls initially
	for i := 0; i < max; i++ {
		key := uint32(i)
		if err := m.Put(key, ignoreFd); err != nil {
			log.Fatalf("put into syscall[%d]: %d %v", i, ignoreFd, err)
		}
	}

	//  Only enable few syscalls which are of the interest
	if err := m.Put(uint32(59), execFd); err != nil {
		log.Fatalf("put into syscall[59]: %v", err)
	}
	if err := m.Put(uint32(222), timerFd); err != nil {
		log.Fatalf("put into syscall[222]: %v", err)
	}
	if err := m.Put(uint32(223), timerFd); err != nil {
		log.Fatalf("put into syscall[223]: %v", err)
	}
	if err := m.Put(uint32(224), timerFd); err != nil {
		log.Fatalf("put into syscall[224]: %v", err)
	}
	if err := m.Put(uint32(225), timerFd); err != nil {
		log.Fatalf("put into syscall[225]: %v", err)
	}
	if err := m.Put(uint32(226), timerFd); err != nil {
		log.Fatalf("put into syscall[226]: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("detaching and exiting")
}
