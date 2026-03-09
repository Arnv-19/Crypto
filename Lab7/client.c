#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "dh.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

// Hardcoded prime P and generator G for simplicity
// Must match the server!
#define P 23
#define G 9

int main() {
    WSADATA wsa;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serv_addr;
    
    // Seed random number generator
    srand(time(NULL) ^ 12345); // Different seed from server

    // 1. Generate Client's Private Key (b)
    // Needs to be between 1 and P-1
    long long int private_key_b = (rand() % (P - 2)) + 1; 
    
    // 2. Generate Client's Public Key (B)
    // B = (G^b) mod P
    long long int public_key_B = power(G, private_key_b, P);
    
    printf("Client Diffie-Hellman Initialization:\n");
    printf("  Prime (P): %d\n", P);
    printf("  Generator (G): %d\n", G);
    printf("  Client Private Key (b): %lld\n", private_key_b);
    printf("  Client Public Key (B): %lld\n\n", public_key_B);
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation error.\n");
        return 1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed.\n");
        return 1;
    }
    printf("--- Connected to server ---\n");
    
    // 3. Exchange Public Keys
    // First, Receive Server's Public Key (A)
    long long int public_key_A;
    recv(sock, (char*)&public_key_A, sizeof(public_key_A), 0);
    printf("Received Server Public Key (A): %lld\n", public_key_A);
    
    // Second, Send Client's Public Key (B)
    send(sock, (char*)&public_key_B, sizeof(public_key_B), 0);
    printf("Sent Client Public Key (B) to Server.\n");
    
    // 4. Generate Shared Secret
    // Shared Secret = (A^b) mod P
    long long int shared_secret = power(public_key_A, private_key_b, P);
    printf(">> Calculated Shared Secret Key: %lld <<\n\n", shared_secret);
    
    // 5. CLI Loop for sending messages and Replay Attacks
    char last_encrypted_message[BUFFER_SIZE];
    int last_msg_len = 0;
    
    while(1) {
        printf("\nOptions:\n");
        printf("1. Send a new message\n");
        printf("2. Execute Replay Attack (Resend last encrypted packet)\n");
        printf("3. Exit\n");
        printf("Choice: ");
        
        int choice;
        scanf("%d", &choice);
        getchar(); // consume newline
        
        if (choice == 3) break;
        
        if (choice == 1) {
            char message[BUFFER_SIZE];
            printf("Enter a message to send to the server: ");
            fgets(message, BUFFER_SIZE, stdin);
            message[strcspn(message, "\n")] = 0; // Remove newline
            int msg_len = strlen(message);
            
            printf("Original Message: %s\n", message);
            
            // Encrypt the message
            encrypt_decrypt(message, msg_len, shared_secret);
            printf("Encrypted Message: ");
            for (int i=0; i < msg_len; i++) printf("%02X ", (unsigned char)message[i]);
            printf("\n");
            
            // Send length, then message
            send(sock, (char*)&msg_len, sizeof(msg_len), 0);
            send(sock, message, msg_len, 0);
            printf("Encrypted message sent to server.\n");
            
            // Save for replay attack
            memcpy(last_encrypted_message, message, msg_len);
            last_msg_len = msg_len;
            
        } else if (choice == 2) {
            if (last_msg_len == 0) {
                printf("No prior message to replay!\n");
                continue;
            }
            printf("\n[ATTACK] Replaying previous encrypted packet to the server...\n");
            printf("Encrypted Payload sent: ");
            for (int i=0; i < last_msg_len; i++) printf("%02X ", (unsigned char)last_encrypted_message[i]);
            printf("\n");
            
            // Blindly resend the EXACT same encrypted packet
            send(sock, (char*)&last_msg_len, sizeof(last_msg_len), 0);
            send(sock, last_encrypted_message, last_msg_len, 0);
            printf("[ATTACK] Replay packet sent successfully.\n");
        } else {
            printf("Invalid choice.\n");
        }
    }
    closesocket(sock);
    WSACleanup();
    
    return 0;
}
