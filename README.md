# learning-ebpf-go

learning-ebpf-go 🐝

A Go-native port and companion to learning-ebpf by Liz Rice — implemented using libbpf, cilium/ebpf, and BPF CO-RE where relevant.

This repository re-implements (and experiments with) the examples from the book using Go, making them easier to explore for developers coming from a Go background.

🚀 What is this?

The original repo from the book is here:
https://github.com/lizrice/learning-ebpf

This repository recreates many of those examples using Go + cilium/ebpf.

The goal is not to replace the original but to provide:

A Go-idiomatic companion,

Using modern CO-RE techniques,

With auto-generated .bpf.o files for convenience.

Note: This is an unofficial companion.
Liz Rice and Isovalent do not endorse or support this repo.
This is my own work, inspired by the book.

📦 Core tools & technologies

This repo uses:

libbpf

For loading BPF programs, CO-RE relocations, and kernel BTF interaction.

cilium/ebpf

The Go library used to:

load BPF objects,

attach tracepoints / kprobes,

interact with maps,

read from ring buffers and perf event arrays.

BPF CO-RE (Compile Once – Run Everywhere)

Allows the BPF programs to run across kernel versions by resolving kernel struct types with BTF, not hardcoding layout offsets.

Pre-compiled .o files

Using bpf2go, each example includes a pre-built BPF object so you can run the Go program without having a C toolchain installed.

📚 Repository Progress
Chapter	Status	Notes
Chapter 1	—	Mostly conceptual
Chapter 2	✅ Implemented	Includes ring buffer + tracepoint example (openat)
Later chapters	⏳ Planned	Contributions welcome
🛠️ Running the examples

Clone and enter the repo:

git clone https://github.com/ArchieSpinos/learning-ebpf-go
cd learning-ebpf-go


If you modify any BPF C code, rebuild the .o files:

go generate ./...


Build and run a chapter example:

go build ./chapter2/hello_file_ring_buffer
sudo ./hello_file_ring_buffer


You should now see output like:

File <fd> - <filename> opened by <command>

✅ What Works

Tracing openat() using tracepoints.

Sending events from kernel → userspace via BPF ring buffer.

CO-RE support through vmlinux.h.

Working Go loader programs using cilium/ebpf.

⚠️ Known Limitations

Only early chapters implemented so far.

Requires a kernel with:

BTF enabled,

ring buffer support (5.8+ recommended),

eBPF syscall permissions (CAP_BPF, CAP_SYS_ADMIN or root).

🙋 Why this exists

To learn eBPF from a Go developer’s perspective.

To practice writing CO-RE-based BPF programs.

To provide a companion resource for the book but in Go, not C.

To serve as a launchpad for further experimentation.

📝 Acknowledgements & Disclaimer

Inspired by learning-ebpf by Liz Rice.

Original examples and book belong to Liz Rice & the eBPF community.

This repo is not affiliated with or endorsed by Liz Rice or Isovalent.

All implementations here are my own work.

🧑‍💻 Contributing

Want to help?

Fork the repo

Add or port an example

Test it

Open a PR

All contributions are welcome — especially ports of later chapters.

🧭 Future Directions

Port more chapters from the book (XDP, LSM, maps, tail calls, etc.)

Add CI for building and validating BPF objects.

Create helper tools and wrappers for common patterns.

Add extended examples (network tracing, file monitoring, syscall filtering).

💬 Questions?

Open an issue or discussion in this repo — happy to chat or help brainstorm.

clang -O2 -g -target bpf  -I/usr/include   -I/usr/include/x86_64-linux-gnu   -I/usr/include/bpf   -c hello.bpf.c -o hello.bpf.o

sudo -E bash -lc 'ulimit -l unlimited && go run .'

troubleshoot

sudo bpftool prog load hello_file_ring_buffer.bpf.o /sys/fs/bpf/test_prog
dmesg | tail -n 30

is the feature supported?
sudo bpftool feature probe | grep -i ringbuf