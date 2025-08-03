#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>

void setup(){
    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int main(){
    setup();

    void* shellcode = mmap(NULL, 22, PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0); // you need only 22 bytes
    
    puts("Enter the code you want to execute: ");
    read(0, shellcode, 22);
    goto *shellcode;

    return 0;
}