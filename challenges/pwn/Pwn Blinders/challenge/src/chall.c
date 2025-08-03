#include <stdio.h>
#include <stdlib.h>

void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
}

void vuln(){
    char buf[32];
    printf("Give me 32 bytes to read: ");
    fgets(buf, 120, stdin);
}

int main(){
    setup();
    printf("fread() at: %p\n", &fread);
    printf("fwrite() at: %p\n", &fwrite);
    printf("fseek() at: %p\n", &fseek);
    vuln();
    return 0 ;
}