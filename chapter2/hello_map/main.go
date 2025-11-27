package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs hello_mapObjects
	if err := loadHello_mapObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	link, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.Hello,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	log.Println("attached raw tracepoint to sys_enter")

	var key uint32
	var value uint64

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			iter := objs.CounterTable.Iterate()
			for iter.Next(&key, &value) {
				log.Printf("ID %d: %d", key, value)
			}
		case <-stop:
			log.Println("stopping")
			return
		}
	}

}
