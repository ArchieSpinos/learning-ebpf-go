# learning-ebpf-go


clang -O2 -g -target bpf  -I/usr/include   -I/usr/include/x86_64-linux-gnu   -I/usr/include/bpf   -c hello.bpf.c -o hello.bpf.o

sudo -E bash -lc 'ulimit -l unlimited && go run .'

troubleshoot

sudo bpftool prog load hello_file_ring_buffer.bpf.o /sys/fs/bpf/test_prog
dmesg | tail -n 30

is the feature supported?
sudo bpftool feature probe | grep -i ringbuf