#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEY_SIZE 4
#define BUF_SIZE 36
#define OUTPUT_SIZE 48

unsigned int generateDynamicKey() {
    srand(time(NULL));
    return (unsigned int) rand();
}

void encrypt(char *input, unsigned int key, char *output) {
    char* head = input;
    unsigned int number;
    char* hOutput = output;

    for(int i = 0; i < strlen(input); i += KEY_SIZE, head += KEY_SIZE, hOutput += KEY_SIZE){
        memcpy(&number, head, KEY_SIZE);
        number ^= key;
        memcpy(hOutput, &number, KEY_SIZE);
    }

    output[strlen(input)] = '\0';
}

void hexDump(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", (unsigned char)data[i]);
    }
    printf("\n");
}

int main(int argc, char const *argv[]) {
    char buf[BUF_SIZE], rslt[OUTPUT_SIZE];
    unsigned int key;

    memset(buf, 0, sizeof(buf));
    memset(rslt, 0, sizeof(rslt));
    
    printf("Enter what you want to encrypt: ");
    fgets(buf, BUF_SIZE, stdin);
    buf[strcspn(buf, "\n")] = 0;

    key = generateDynamicKey();
    printf("Using key: 0x%08x\n", key);
    
    encrypt(buf, key, rslt);

    printf("Encrypted output (hex): ");
    hexDump(rslt, strlen(buf));

    return 0;
}