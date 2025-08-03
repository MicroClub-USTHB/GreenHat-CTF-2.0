#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#define TIME_LIMIT 10  // seconds

void timeout_handler(int sig) {
    (void)sig;
    puts("\nTime's up! Try scripting faster next time.");
    exit(1);
}

void setup(){
    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // install alarm handler
    signal(SIGALRM, timeout_handler);
    alarm(TIME_LIMIT);
}

void flag(){
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

void vuln(){
    
    srand(time(NULL));
    short int target = - (rand() % 1000 + 2);

    printf("Your target sum is: %d\n", target);
    printf("Enter two non-negative numbers a and b such that a + b == target\n");

    short int a = 0, b = 0;
    printf("a = ");
    if (scanf("%hd", &a) != 1) {
        puts("Invalid input!");
        exit(1);
    }
    printf("b = ");
    if (scanf("%hd", &b) != 1) {
        puts("Invalid input!");
        exit(1);
    }

    if (a < 0 || b < 0) {
        puts("No negative numbers allowed!");
        exit(1);
    }
    if ((short)(a + b) == target) {
        flag();
    } else {
        printf("Nope: %hd + %hd = %hd\n", a, b, a + b);
    }
}

int main(){
    setup();
    vuln();
    return 0;
}
