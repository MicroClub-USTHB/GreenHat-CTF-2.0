// gcc -fstack-protector-all -z relro -z now -pie -fPIE challenge/src/unusual.c -o challenge/src/unusual && cp challenge/src/unusual assets
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>

#define PAGE_SIZE 0x1000

static const char rodata_str[] = "ghctf{example_flag}";
bool is_NameSet = false;

__attribute__((constructor))
void libc_constructor() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    uintptr_t addr = (uintptr_t)rodata_str & ~(PAGE_SIZE - 1);
    mprotect((void *)addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

void SetName(){
    char name[6];

    memset(name, 0, sizeof(name));

    printf("Please Input your name: ");
    scanf("%5s", name);

    printf("Welcome, ");
    printf(name);

    is_NameSet = true;
}

void SetAddr() {
    uintptr_t addr;
    char buf[32];

    memset(buf, 0, sizeof(buf));

    printf("Enter the Address you want to overwrite: ");
    scanf("%lx", &addr);

    printf("Enter What you want to overwrite it with: ");
    scanf("%31s", buf);

    memcpy((void *)addr, buf, 8);
}

void ListCurrentDir(){
    puts("Listing Current Directory...");
    system("ls -lAh");

    return;
}

void printMenu(){
    puts("\nWelcome to your final challenge!");
    puts("1- Update/Set your name");
    puts("2- Change an address in memory");
    puts("3- List Current Directory");
    puts("4- Quit");

    printf("Your Choice: ");
}

int main(int argc, char const *argv[]){
    int choice;
    while (true){
        printMenu();
        while ((choice = getchar()) == 0x0A);
        
        switch (choice){
        case '1':
            if (is_NameSet){
                puts("Name Already set!");
            }
            else {
                SetName();
            }
            break;

        case '2':
            SetAddr();
            break;

        case '3':
            ListCurrentDir();
            break;
        
        case '4':
            puts("GoodBye!");
            _exit(0);
            break;

        default:
            puts("Wrong Choice, Exiting...");
            _exit(0);
        }
    }

    return 0;
}