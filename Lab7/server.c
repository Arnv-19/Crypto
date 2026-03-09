#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "dh.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8081
#define BUFFER_SIZE 1024

// Hardcoded prime P and generator G for simplicity
// In reality, these should be securely generated large primes
#define P 23
#define G 9

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in server, client;
    int c;
    
    // Seed random number generator
    srand(time(NULL));

    // 1. Generate Server's Private Key (a)
    // Needs to be between 1 and P-1
    long long int private_key_a = (rand() % (P - 2)) + 1; 
    
    // 2. Generate Server's Public Key (A)
    // A = (G^a) mod P
    long long int public_key_A = power(G, private_key_a, P);
    
    printf("Server Diffie-Hellman Initialization:\n");
    printf("  Prime (P): %d\n", P);
    printf("  Generator (G): %d\n", G);
    printf("  Server Private Key (a): %lld\n", private_key_a);
    printf("  Server Public Key (A): %lld\n\n", public_key_A);

    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d\n", WSAGetLastError());
        return 1;
    }
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d\n", WSAGetLastError());
        return 1;
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d\n", WSAGetLastError());
        return 1;
    }
    
    listen(server_fd, 3);
    
    printf("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    
    while((new_socket = accept(server_fd, (struct sockaddr *)&client, &c)) != INVALID_SOCKET) {
        printf("\n--- Client Connected ---\n");
        
        // 3. Exchange Public Keys
        // First, Send Server's Public Key (A)
        send(new_socket, (char*)&public_key_A, sizeof(public_key_A), 0);
        printf("Sent Server Public Key (A) to Client.\n");
        
        // Second, Receive Client's Public Key (B)
        long long int public_key_B;
        recv(new_socket, (char*)&public_key_B, sizeof(public_key_B), 0);
        printf("Received Client Public Key (B): %lld\n", public_key_B);
        
        // 4. Generate Shared Secret
        // Shared Secret = (B^a) mod P
        long long int shared_secret = power(public_key_B, private_key_a, P);
        printf(">> Calculated Shared Secret Key: %lld <<\n\n", shared_secret);
        
        // 5. Receive encrypted data from client AND decrypt it (LOOP)
        while(1) {
            int msg_len;
            if (recv(new_socket, (char*)&msg_len, sizeof(msg_len), 0) <= 0) {
                printf("\nClient disconnected.\n");
                break;
            }
            
            char *encrypted_message = (char *)malloc(msg_len + 1);
            recv(new_socket, encrypted_message, msg_len, 0);
            encrypted_message[msg_len] = '\0';
            
            printf("Received Encrypted Message:\n");
            for (int i=0; i < msg_len; i++) printf("%02X ", (unsigned char)encrypted_message[i]);
            printf("\n");
            
            // Decrypt the message
            encrypt_decrypt(encrypted_message, msg_len, shared_secret);
            
            printf("Decrypted Message: %s\n\n", encrypted_message);
            
            free(encrypted_message);
        }
        
        closesocket(new_socket);
    }
    
    if (new_socket == INVALID_SOCKET) {
        printf("accept failed with error code : %d\n", WSAGetLastError());
        return 1;
    }
    
    closesocket(server_fd);
    WSACleanup();
    
    return 0;
}
