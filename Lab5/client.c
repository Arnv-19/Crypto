#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

void print_hex(uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error.\n");
        return 1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Legacy
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Connect
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed.\n");
        return 1;
    }
    printf("Connected to server.\n");
    
    // User Input
    int op, mode, key_int, iv_int, data_len;
    uint8_t op_byte, mode_byte, iv_byte;
    uint16_t key_uint16;
    
    printf("Enter Operation (0 for Encrypt, 1 for Decrypt): ");
    scanf("%d", &op);
    op_byte = (uint8_t)op;
    
    printf("Enter Mode (0:ECB, 1:CBC, 2:CFB, 3:OFB, 4:CTR): ");
    scanf("%d", &mode);
    mode_byte = (uint8_t)mode;
    
    printf("Enter 10-bit Key (0-1023): ");
    scanf("%d", &key_int);
    key_uint16 = (uint16_t)key_int;
    
    printf("Enter IV/Counter (8-bit, 0-255): ");
    scanf("%d", &iv_int);
    iv_byte = (uint8_t)iv_int;
    
    printf("Enter Data Length: ");
    scanf("%d", &data_len);
    
    uint8_t *data = (uint8_t *)malloc(data_len);
    printf("Enter %d bytes of data (space separated integers 0-255):\n", data_len);
    for (int i = 0; i < data_len; i++) {
        int val;
        scanf("%d", &val);
        data[i] = (uint8_t)val;
    }
    
    // Send Request
    send(sock, (char*)&op_byte, 1, 0);
    send(sock, (char*)&mode_byte, 1, 0);
    send(sock, (char*)&key_uint16, 2, 0);
    send(sock, (char*)&iv_byte, 1, 0);
    send(sock, (char*)&data_len, 4, 0);
    send(sock, (char*)data, data_len, 0);
    
    // Receive Response
    uint8_t *response = (uint8_t *)malloc(data_len);
    int total_received = 0;
    while (total_received < data_len) {
        int bytes = recv(sock, (char*)response + total_received, data_len - total_received, 0);
         if (bytes == SOCKET_ERROR || bytes == 0) break;
        total_received += bytes;
    }
    
    printf("Result (Hex): ");
    print_hex(response, data_len);
    
    printf("Result (Dec): ");
    for (int i = 0; i < data_len; i++) {
        printf("%d ", response[i]);
    }
    printf("\n");
    
    free(data);
    free(response);
    closesocket(sock);
    WSACleanup();
    
    return 0;
}
