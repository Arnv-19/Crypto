#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <conio.h>
#include <time.h>
#include "sss.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_CLIENTS 50

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
    srand(time(NULL));
    
    WSADATA wsa;
    SOCKET server_fd, client_sockets[MAX_CLIENTS];
    int n_clients = 0;
    int m_threshold = 0;
    int secretS = 0;
    
    // Server states
    int state = 0; // 0 = ACCEPTING, 1 = IDLE, 2 = POLLING
    
    int requester_index = -1;
    Share received_shares[MAX_CLIENTS];
    int yes_votes = 0;
    int responses_received = 0;

    printf("\nInitializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        return 1;
    }

    struct sockaddr_in server, client;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code: %d\n", WSAGetLastError());
        return 1;
    }

    // Set server socket to non-blocking
    u_long mode = 1;
    ioctlsocket(server_fd, FIONBIO, &mode);
    listen(server_fd, MAX_CLIENTS);
    
    printf("Server started. Listening on port %d.\n", PORT);
    printf("Type 'completed' when all clients have connected.\n\n");

    char input_buf[256];
    int buf_len = 0;

    while (1) {
        // --- 1. Terminal non-blocking input handling ---
        if (_kbhit()) {
            char ch = _getch();
            if (ch == '\r' || ch == '\n') {
                input_buf[buf_len] = '\0';
                printf("\n");
                
                if (state == 0 && strcmp(input_buf, "completed") == 0) {
                    if (n_clients == 0) {
                        printf("Cannot complete with 0 clients connected.\n");
                    } else {
                        printf("\n--- Generating Shares ---\n");
                        state = 1; // Move to IDLE state
                        m_threshold = (n_clients / 2) + 1;
                        secretS = rand() % P;
                        int degree = m_threshold - 1;
                        int coeffs[MAX_CLIENTS];
                        coeffs[0] = secretS;
                        
                        printf("Number of clients: %d\n", n_clients);
                        printf("Calculated Threshold (M): %d\n", m_threshold);
                        printf("Generated Secret S: %d\n", secretS);
                        for (int i = 1; i <= degree; i++) {
                            coeffs[i] = rand() % P;
                        }
                        
                        // Distribute to all clients
                        for (int i = 0; i < n_clients; i++) {
                            Share share;
                            share.x = i + 1;
                            share.y = evaluatePolynomial(coeffs, degree, share.x);
                            
                            Message msg;
                            msg.type = MSG_ASSIGN_SHARE;
                            msg.share = share;
                            
                            send(client_sockets[i], (char*)&msg, sizeof(Message), 0);
                            printf("Distributed Share (x=%d, y=%d) to Client %d\n", share.x, share.y, i+1);
                        }
                        printf("\nServer is now IDLE. Waiting for access requests from clients.\n");
                    }
                }
                buf_len = 0; // Reset buffer
            } else if (ch == '\b') {
                if (buf_len > 0) {
                    buf_len--;
                    printf("\b \b");
                }
            } else {
                input_buf[buf_len++] = ch;
                printf("%c", ch);
            }
        }

        // --- 2. Network non-blocking select ---
        fd_set readfds;
        FD_ZERO(&readfds);
        
        if (state == 0) {
            FD_SET(server_fd, &readfds); // Only listen for new connections in ACCEPTING state
        }
        
        for (int i = 0; i < n_clients; i++) {
            FD_SET(client_sockets[i], &readfds);
        }

        struct timeval tv = {0, 10000}; // 10ms
        int activity = select(0, &readfds, NULL, NULL, &tv);
        
        if (activity == SOCKET_ERROR) {
            continue;
        }

        // Handle new connections
        if (state == 0 && FD_ISSET(server_fd, &readfds)) {
            int c = sizeof(struct sockaddr_in);
            SOCKET new_socket = accept(server_fd, (struct sockaddr *)&client, &c);
            if (new_socket != INVALID_SOCKET) {
                // Set client socket to non-blocking
                u_long client_mode = 1;
                ioctlsocket(new_socket, FIONBIO, &client_mode);
                client_sockets[n_clients++] = new_socket;
                printf("Client %d connected.\n", n_clients);
            }
        }

        // Handle client messages
        for (int i = 0; i < n_clients; i++) {
            if (FD_ISSET(client_sockets[i], &readfds)) {
                Message msg;
                int valread = recv(client_sockets[i], (char*)&msg, sizeof(Message), 0);
                
                if (valread > 0) {
                    if (state == 1 && msg.type == MSG_REQUEST_ACCESS) {
                        // Client is requesting access
                        printf("\n>>> Client %d is requesting access to the secret! <<<\n", i+1);
                        state = 2; // Move to POLLING state
                        requester_index = i;
                        yes_votes = 1; // Requester inherently votes yes with their own share
                        responses_received = 1; // Self response
                        
                        // Add requester's share to the list
                        received_shares[0] = msg.share;
                        
                        // Broadcast REQUEST_SHARE to all OTHER clients
                        for (int j = 0; j < n_clients; j++) {
                            if (j != requester_index) {
                                Message req;
                                req.type = MSG_REQUEST_SHARE;
                                send(client_sockets[j], (char*)&req, sizeof(Message), 0);
                            }
                        }
                        
                        if (n_clients == 1) { // Edge case: only 1 client connected
                            // Process immediately (it will fail if threshold > 1 but theoretically it evaluates)
                            goto evaluate_access;
                        }
                        
                    } else if (state == 2 && (msg.type == MSG_RESPONSE_YES || msg.type == MSG_RESPONSE_NO)) {
                        responses_received++;
                        if (msg.type == MSG_RESPONSE_YES) {
                            printf("Client %d: YES, received share (x=%d, y=%d)\n", i+1, msg.share.x, msg.share.y);
                            received_shares[yes_votes++] = msg.share;
                        } else {
                            printf("Client %d: NO, declined to send share.\n", i+1);
                        }
                        
                        if (responses_received == n_clients) {
evaluate_access:
                            // All responses collected
                            printf("\n--- Polling Complete ---\n");
                            printf("Total YES shares: %d (Minimum required: %d)\n", yes_votes, m_threshold);
                            
                            Message result_msg;
                            if (yes_votes >= m_threshold) {
                                int reconstructedS = lagrangeInterpolate(received_shares, m_threshold);
                                printf("SUCCESS! Secret reconstructed: %d\n", reconstructedS);
                                if (reconstructedS == secretS) {
                                    printf("Verification Passed! Granting access to Client %d.\n", requester_index+1);
                                    result_msg.type = MSG_ACCESS_GRANTED;
                                    // Send the secret for the client to verify
                                    result_msg.share.x = 0;
                                    result_msg.share.y = secretS; 
                                } else {
                                    printf("Reconstruction logic failed.\n");
                                    result_msg.type = MSG_ACCESS_REJECTED;
                                }
                            } else {
                                printf("FAIL! Insufficient shares. Rejecting access to Client %d.\n", requester_index+1);
                                result_msg.type = MSG_ACCESS_REJECTED;
                            }
                            
                            // Send result to the requester
                            send(client_sockets[requester_index], (char*)&result_msg, sizeof(Message), 0);
                            
                            // Reset state to IDLE
                            state = 1;
                            printf("\nServer is now IDLE. Waiting for access requests from clients.\n");
                        }
                    }
                } else if (valread <= 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
                    // Client disconnected
                    printf("Client %d disconnected unexpectedly.\n", i+1);
                    closesocket(client_sockets[i]);
                    client_sockets[i] = 0;
                    // For a robust system we'd manage the array, but for this lab simplifying
                }
            }
        }
        
        Sleep(10); // Sleep briefly to prevent high CPU usage in while(1) loop
    }

    for (int i = 0; i < n_clients; i++) {
        closesocket(client_sockets[i]);
    }
    closesocket(server_fd);
    WSACleanup();

    return 0;
}
