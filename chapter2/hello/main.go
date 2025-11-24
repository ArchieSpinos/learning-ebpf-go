package main

import (
	"log"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
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
	spec, err := ebpf.LoadCollectionSpec("bpf/hello.bpf.o")
	if err != nil {
		log.Fatal(err)
	}

	objs := struct {
		Hello *ebpf.Program `ebpf:"hello"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Hello.Close()

	event := syscallName("execve")

	kp, err := link.Kprobe(event, objs.Hello, nil)
	if err != nil {
		log.Fatalf("attach kprobe: %v", err)
	}
	defer kp.Close()

	log.Printf("attached kprobe to %s", event)
	select {}
}
