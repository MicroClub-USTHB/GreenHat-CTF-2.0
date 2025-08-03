// gcc -Wall src/secret.c -o ../assets/secret && strip ../assets/secret
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define PORT 13800
#define BUFFER_SIZE 1024
#define PAYLOAD_SIZE 32

int server_fd;

typedef struct __attribute__((__packed__)) Packet{
    uint32_t id;
    uint8_t data_key;
    uint8_t chcksum_key;
    uint8_t service_code;
    char data[PAYLOAD_SIZE];
    uint64_t checksum;
} Packet;

void print_flag(uint32_t fd) {
    send(fd, "Oomph, now that was unexpected.\nFine, here's your flag: ", sizeof("Oomph, now that was unexpected.\nFine, here's your flag: "), 0);

    FILE *fp = fopen("./flag", "r");
    if (!fp) {
        perror("[ERROR] Failed to open flag file");
        return;
    }

    char flag[64];
    if (fgets(flag, sizeof(flag), fp) == NULL) {
        perror("[ERROR] Failed to read flag");
        fclose(fp);
        return;
    }

    fclose(fp);

    send(fd, flag, strlen(flag), 0);

    return;
}

bool check_id(uint32_t expected_id, Packet* packet){
    return packet->id == expected_id;
}

uint64_t calculate_checksum(Packet* packet) {
    uint64_t sum = packet->id;
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        sum += (unsigned char) packet->data[i] ^ packet->chcksum_key;
    }
    return sum;
}

bool check_checksum(Packet* packet) {
    return calculate_checksum(packet) == packet->checksum;
}

void signal_error(uint32_t fd, char* field){
    char message[128];
    int written = sprintf(message, "[ERROR]: Found Error in the '%s' field.\n", field);
    send(fd, message, written, 0);
}

void get_word(Packet* packet, char* output){
    for(int i = 0; i < PAYLOAD_SIZE; i++){
        output[i] = (unsigned char) packet->data[i] ^ packet->data_key;
    }
    return;
}

void handle_packet(uint32_t fd, uint32_t expected_id, const char *data, ssize_t length) {
    if ((size_t)length < sizeof(Packet)) {
        send(fd, "[ERROR]: Incomplete packet received.", sizeof("[ERROR]: Incomplete packet received."), 0);
        return;
    }

    Packet* packet = (Packet*) data;
    char word[PAYLOAD_SIZE];
    char expected[PAYLOAD_SIZE];

    memset(word, 0, sizeof(word));
    memset(expected, 0, sizeof(expected));

    strcpy(expected, "flag");

    if (!check_id(expected_id, packet)){
        signal_error(fd, "ID");
        return;
    }

    if (!check_checksum(packet)) {
        signal_error(fd, "Checksum");
        return;
    }

    switch (packet->service_code){
        case 0x01:
            send(fd, "Hello World!", sizeof("Hello World!"), 0);
            break;

        case 0x02:
            send(fd, "Try a bit harder, will ya'?", sizeof("Try a bit harder, will ya'?"), 0);
            break;
        
        case 0x03:
            send(fd, "You're still here ? tsk tsk", sizeof("You're still here ? tsk tsk"), 0);
            break;
        
        case 0xFF:
            get_word(packet, word);
            if(memcmp(word, expected, PAYLOAD_SIZE)){
                send(fd, "Phew... that was close!", sizeof("Phew... that was close!"), 0);
            }
            else
                print_flag(fd);
            break;

        default:
            send(fd, "Feature not yet available!", sizeof("Feature not yet available!"), 0);
            break;
    }
}

int start_listener(uint16_t port){
    int server_fd;
    struct sockaddr_in server_addr;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

int main() {
    int client_fd;
    struct sockaddr_in client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);
    ssize_t bytes_received;
    uint32_t cur_id = 0;

    server_fd = start_listener(PORT);

    printf("[+] Listening on port %d...\n", PORT);

    while (1) {
        // Accept a client connection
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("accept");
            continue;
        }

        printf("[*] Connection received from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }
        else {
            // Receive data and pass to handler
            while ((bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0)) > 0){
                handle_packet(client_fd, cur_id, buffer, bytes_received);
            }
            if (bytes_received < 0)
                perror("recv");
    
            close(client_fd);
            printf("[*] Connection closed\n");
        }
    }

    close(server_fd);
    return 0;
}
