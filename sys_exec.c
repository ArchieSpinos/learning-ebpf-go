#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

ssize_t my_write(int fd, const void *buf, size_t size) {
    return syscall(SYS_write, fd, buf, size);
}

int main(void)
{
    const char hello[] = "Hello world!\n";

    ssize_t n = my_write(STDOUT_FILENO, hello, sizeof(hello) - 1);

    if (n < 0) {
        perror("my_write");
    }

    return 0;
}
