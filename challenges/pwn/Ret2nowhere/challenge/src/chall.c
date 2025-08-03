#include <stdio.h>
#include <stdlib.h>

char BIN_SH[8] = "/bin/sh";

void gadget() {
    asm volatile ("pop %%rdi\n\tret":::"rdi");
}

void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);

    system(NULL); // useless
}

void vuln(){
    char buf[64];
    fgets(buf, 512, stdin);
}

int main(){
    setup();
    printf("Main at: %p\n", &main);
    vuln();
    return 0 ;
}