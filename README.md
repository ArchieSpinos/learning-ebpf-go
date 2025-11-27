# learning-ebpf-go


clang -O2 -g -target bpf  -I/usr/include   -I/usr/include/x86_64-linux-gnu   -I/usr/include/bpf   -c hello.bpf.c -o hello.bpf.o

sudo -E bash -lc 'ulimit -l unlimited && go run .'