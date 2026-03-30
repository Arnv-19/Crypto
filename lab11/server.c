#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "common.h"
#include "sdes.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_CLIENTS 50

// Hardcoded Master Keys for simulation (10-bit size since SDES specification requires 10-bit keys)
#define CLIENT_KEY  0x1A3
#define SERVER_KEY  0x3BF

int main() {
    srand(time(NULL));
    WSADATA wsa;
    SOCKET server_fd, client_sockets[MAX_CLIENTS];

    printf("===================================================\n");
    printf("--- Kerberos Authenticator (KDC & Service Host) ---\n");
    printf("===================================================\n");
    
    printf("Initializing Winsock...\n");
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

    u_long mode = 1;
    ioctlsocket(server_fd, FIONBIO, &mode);
    listen(server_fd, MAX_CLIENTS);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
    }

    printf("Online! Waiting for clients to request tokens on port %d...\n\n", PORT);

    while(1) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] > 0) {
                FD_SET(client_sockets[i], &readfds);
            }
        }

        struct timeval tv = {0, 10000};
        int activity = select(0, &readfds, NULL, NULL, &tv);

        if (activity == SOCKET_ERROR) continue;

        if (FD_ISSET(server_fd, &readfds)) {
            int c = sizeof(struct sockaddr_in);
            SOCKET new_socket = accept(server_fd, (struct sockaddr *)&client, &c);
            if (new_socket != INVALID_SOCKET) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (client_sockets[i] == 0) {
                        client_sockets[i] = new_socket;
                        printf("\n#######################################################\n");
                        printf("[SERVER] Incoming Multi-Client Connection Accepted! (Slot %d)\n", i+1);
                        break;
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            SOCKET sock = client_sockets[i];
            if (sock > 0 && FD_ISSET(sock, &readfds)) {
                int type;
                int read_size = recv(sock, (char*)&type, sizeof(int), MSG_PEEK);
                
                if (read_size <= 0) {
                    printf("\n[SERVER] Client in slot %d disconnected.\n", i+1);
                    closesocket(sock);
                    client_sockets[i] = 0;
                    continue;
                }

                if (type == MSG_REQ_TGT) {
                    MsgReqTgt req;
                    recv(sock, (char*)&req, sizeof(MsgReqTgt), 0);
                    
                    printf("\n[KDC Client %d] --> Received TGT Token REQUEST from ID: '%s'\n", i+1, req.client_id);
                    
                    // The core generation logic as requested
                    printf("[KDC Client %d] [STEP 1] Generating secure Session Key...\n", i+1);
                    uint16_t session_key = rand() % 0x3FF; // Needs a secure 10-bit random number for SDES
                    printf("                         Algorithm: stdlib rand() casted to 10-bit uint16_t\n");
                    printf("                         Generated Session Key Value: 0x%03X\n", session_key);

                    MsgResTgt res;
                    res.type = MSG_RES_TGT;
                    
                    // Package encryption blocks
                    printf("[KDC Client %d] [STEP 2] Encrypting Token and Session Key...\n", i+1);
                    printf("                         Encrypting Session Key with Algorithm: SDES (ECB mode).\n");
                    printf("                         Using Key: Client Master Key Kc (0x%03X)\n", CLIENT_KEY);
                    
                    uint8_t sk_bytes[2];
                    sk_bytes[0] = (session_key >> 8) & 0xFF;
                    sk_bytes[1] = session_key & 0xFF;
                    encrypt_ecb(sk_bytes, 2, CLIENT_KEY, res.enc_session_key);
                    
                    char token_plain[32];
                    sprintf(token_plain, "%s,%u", req.client_id, session_key);
                    int t_len = strlen(token_plain) + 1;
                    
                    printf("                         Building Token Plaintext Format: '%s'\n", token_plain);
                    printf("                         Encrypting Token with Algorithm: SDES (ECB mode).\n");
                    printf("                         Using Key: Service Server Master Key Ks (0x%03X)\n", SERVER_KEY);
                    encrypt_ecb((uint8_t*)token_plain, t_len, SERVER_KEY, res.enc_token);
                    res.token_len = t_len;
                    
                    send(sock, (char*)&res, sizeof(MsgResTgt), 0);
                    printf("[KDC Client %d] <-- Ticket Response SENT back to Client.\n", i+1);
                    
                } else if (type == MSG_REQ_SRV) {
                    MsgReqSrv req;
                    recv(sock, (char*)&req, sizeof(MsgReqSrv), 0);
                    printf("\n[SERVICE Client %d] --> Received Authentication SERVICE Request.\n", i+1);
                    
                    printf("                   [CRYPTO 1] Decrypting Token utilizing Server Master Key (0x%03X).\n", SERVER_KEY);
                    uint8_t dec_token[32];
                    decrypt_ecb(req.enc_token, req.token_len, SERVER_KEY, dec_token);
                    char *token_str = (char*)dec_token;
                    printf("                              Decrypted Token reveals string: '%s'\n", token_str);
                    
                    char *token_id = strtok(token_str, ",");
                    char *token_sk_str = strtok(NULL, ",");
                    
                    if(token_id == NULL || token_sk_str == NULL) {
                        printf("[SERVICE Client %d]  ERROR: Invalid Token format deciphered! Rejecting immediately.\n", i+1);
                        MsgResSrv res;
                        res.type = MSG_RES_SRV;
                        res.status = 0;
                        send(sock, (char*)&res, sizeof(MsgResSrv), 0);
                    } else {
                        uint16_t session_key = (uint16_t)atoi(token_sk_str);
                        printf("                   [AUTH 1] Token ID Validated    -> %s\n", token_id);
                        printf("                   [AUTH 2] Extracted Session Key -> 0x%03X\n", session_key);
                        
                        printf("                   [CRYPTO 2] Decrypting Authenticator block utilizing exact Session Key.\n");
                        uint8_t dec_auth[32];
                        decrypt_ecb(req.enc_authenticator, req.auth_len, session_key, dec_auth);
                        char *auth_str = (char*)dec_auth;
                        printf("                              Decrypted Authenticator reveals string: '%s'\n", auth_str);
                        
                        char *auth_id = strtok(auth_str, ",");
                        
                        MsgResSrv res;
                        res.type = MSG_RES_SRV;
                        if (auth_id != NULL && strcmp(token_id, auth_id) == 0) {
                            printf("[SERVICE Client %d] => SUCCESS! Token Identity Matches Authenticator Identity.\n", i+1);
                            printf("                       Access Granted to Client.\n");
                            res.status = 1;
                        } else {
                            printf("[SERVICE Client %d] => FAILURE! Mismatch detected. Attempted identity forgery or invalid cypher.\n", i+1);
                            printf("                       Access Denied to Client.\n");
                            res.status = 0;
                        }
                        send(sock, (char*)&res, sizeof(MsgResSrv), 0);
                    }
                } else {
                    char junk[1024];
                    recv(sock, junk, sizeof(junk), 0);
                }
            }
        }
        Sleep(10);
    }

    closesocket(server_fd);
    WSACleanup();
    return 0;
}
