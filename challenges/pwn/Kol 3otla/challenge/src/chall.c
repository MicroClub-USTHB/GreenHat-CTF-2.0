#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void setup(){
    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void flag() {
    FILE* fd = fopen("flag.txt", "r");
    if (!fd){
        perror("fopen");
        exit(-1);
    }
    char flag[0x80];
    fgets(flag, sizeof(flag), fd);
    printf("%s", flag);
    fclose(fd);
    exit(0);
}

void vuln() {
    int check = 0;
    int len;
    char buff[64];

    printf("Fill in the gaps\n");
    printf("Kol 3otla ");
    read(0, buff, 128);
    if (strlen(buff) > 64) {
        printf("Too many characters, fiha khir\n");
        exit(0);
    }
    if (check == 0xdeadbeef) {
        printf("Leet pwner\n");
        flag();
    }
    else if (check != 0) {
        printf("Semi leet pwner, fiha khir\n");
        exit(0);
    }
    printf("Fiha khir\n");
}

int main(){
    setup();
    vuln();
    return 0;
}
