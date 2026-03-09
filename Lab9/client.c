#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <conio.h>
#include "sss.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

// MSG types
#define MSG_ASSIGN_SHARE 1
#define MSG_REQUEST_SHARE 2
#define MSG_RESPONSE_YES 3
#define MSG_RESPONSE_NO 4
#define MSG_REQUEST_ACCESS 5
#define MSG_ACCESS_GRANTED 6
#define MSG_ACCESS_REJECTED 7

typedef struct {
    int type;
    Share share; 
} Message;

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    Share my_share;
    
    int state = 0; // 0 = Connecting/Waiting, 1 = Idle, 2 = Prompting (y/n), 3 = Waiting for result

    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        return 1;
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection error\n");
        return 1;
    }
    
    // Set socket to non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    printf("Connected to server.\n");
    printf("Waiting for the server to distribute shares...\n");

    while(1) {
        // --- 1. Terminal non-blocking input handling ---
        if (_kbhit()) {
            char ch = _getch();
            
            if (state == 1 && (ch == 'r' || ch == 'R')) {
                // Request access
                Message req;
                req.type = MSG_REQUEST_ACCESS;
                req.share = my_share; // Send our own share
                send(sock, (char*)&req, sizeof(Message), 0);
                
                printf("\n>>> Sent access request to Server! <<<\n");
                printf("    Waiting for server to poll other clients...\n");
                state = 3; // Waiting for access result
                
            } else if (state == 2 && (ch == 'y' || ch == 'Y' || ch == 'n' || ch == 'N')) {
                // Respond to share request
                Message reply;
                if (ch == 'y' || ch == 'Y') {
                    reply.type = MSG_RESPONSE_YES;
                    reply.share = my_share;
                    printf("y\n    Sending YES along with share (x=%d, y=%d)...\n", my_share.x, my_share.y);
                } else {
                    reply.type = MSG_RESPONSE_NO;
                    reply.share.x = 0;
                    reply.share.y = 0;
                    printf("n\n    Sending NO. Holding onto share.\n");
                }
                send(sock, (char*)&reply, sizeof(Message), 0);
                state = 1; // Back to Idle
            }
        }
        
        // --- 2. Network non-blocking select ---
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval tv = {0, 10000}; // 10ms
        
        int activity = select(0, &readfds, NULL, NULL, &tv);
        if (activity > 0 && FD_ISSET(sock, &readfds)) {
            Message msg;
            int recv_size = recv(sock, (char*)&msg, sizeof(Message), 0);
            
            if (recv_size > 0) {
                if (state == 0 && msg.type == MSG_ASSIGN_SHARE) {
                    my_share = msg.share;
                    printf("\nReceived my share! (x=%d, y=%d)\n", my_share.x, my_share.y);
                    printf("\n--- Instructions ---\n");
                    printf("Press 'R' at any time to request access to the secret.\n");
                    printf("If prompted, press 'Y' or 'N' to share your key.\n");
                    printf("--------------------\n");
                    state = 1;
                    
                } else if (state == 1 && msg.type == MSG_REQUEST_SHARE) {
                    printf("\n>>> SERVER REQUEST: Another client is requesting access.\n");
                    printf("    Do you want to send your share to help? (y/n): ");
                    state = 2; // Prompting
                    
                } else if (state == 3 && msg.type == MSG_ACCESS_GRANTED) {
                    printf("\n>>> ACCESS GRANTED: Server reconstructed Secret %d.\n", msg.share.y);
                    state = 1;
                    
                } else if (state == 3 && msg.type == MSG_ACCESS_REJECTED) {
                    printf("\n>>> ACCESS REJECTED: Not enough shares.\n");
                    state = 1;
                }
            } else if (recv_size <= 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
                printf("\nServer disconnected. Closing client.\n");
                break;
            }
        }
        Sleep(10);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
