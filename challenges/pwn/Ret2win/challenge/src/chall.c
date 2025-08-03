#include <stdio.h>
#include <stdlib.h>

// gcc chall.c -o chall -fno-stack-protector -no-pie -m32

void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
}

void win(int key){
    if (key == 0xcafebabe) {
        printf("You win!\n");
        system("/bin/sh");
    }

    else printf("You've found the winners spot, you need to know the key to enter\n");
    
    exit(0);
}

void vuln(){
    char buf[64];
    printf("Whats the winners key to success: ");
    fgets(buf, 512, stdin);
}

int main(){
    setup();
    vuln();
    return 0 ;
}