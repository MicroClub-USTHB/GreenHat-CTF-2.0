#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

void setup() {
    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void set_flag(char *flag) {
    int fd = open("flag.txt", 0);
    read(fd, flag, 100);
    close(fd);
}

int main() {
    char buf[16];
    char *flag = malloc(100);
    int i=0;
    setup();
    set_flag(flag);
    printf("Your flag at %p\n", flag);
    while (i<0xff) {
        printf("echo ");
        read(0, buf, 16);
        printf(buf);

        i++;
    }

    return 0; 
}
