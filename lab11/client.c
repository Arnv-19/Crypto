#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "common.h"
#include "sdes.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

// Hardcoded Master Keys for simulation
#define CLIENT_KEY 0x1A3 // Key Kc (10 bits) known by Client & KDC

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    
    printf("==========================================\n");
    printf("--- Kerberos Authentication Client ---\n");
    printf("==========================================\n");
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
    printf("Connected to server (KDC & Service).\n\n");

    // --- STEP 1: Request Token ---
    MsgReqTgt req_tgt;
    req_tgt.type = MSG_REQ_TGT;
    strcpy(req_tgt.client_id, "Arnav");
    
    printf("[STEP 1] Sending Ticket Granting Ticket (TGT) Request to KDC...\n");
    printf("         -> Claiming Client ID: %s\n", req_tgt.client_id);
    send(sock, (char*)&req_tgt, sizeof(MsgReqTgt), 0);

    // --- STEP 2: Receive Token & Encrypted Session Key ---
    MsgResTgt res_tgt;
    int recv_size = recv(sock, (char*)&res_tgt, sizeof(MsgResTgt), 0);
    if (recv_size <= 0) {
        printf("Server disconnected.\n");
        return 1;
    }
    
    if (res_tgt.type != MSG_RES_TGT) {
        printf("Unexpected message from Server.\n");
        return 1;
    }
    printf("\n[STEP 2] Received Response from KDC.\n");
    printf("         -> Included: Encrypted Session Key (2 bytes)\n");
    printf("         -> Included: Encrypted Token (%d bytes)\n", res_tgt.token_len);
    
    // Decrypt session key using CLIENT_KEY
    printf("\n[CRYPTO] Decrypting Session Key using SDES (Simplified DES) in ECB mode.\n");
    printf("         -> Client Master Key (Kc) Used: 0x%03X (10 bits)\n", CLIENT_KEY);
    
    uint8_t dec_sk[2];
    decrypt_ecb(res_tgt.enc_session_key, 2, CLIENT_KEY, dec_sk); // SDES ECB descryption
    
    uint16_t session_key = (dec_sk[0] << 8) | dec_sk[1];
    printf("         -> SUCCESS! Extracted Session Key: 0x%03X\n", session_key);

    // --- STEP 3: Request Actual Service ---
    MsgReqSrv req_srv;
    req_srv.type = MSG_REQ_SRV;
    
    // Copy token over directly (Client cannot read it since it's encrypted with Server's key)
    memcpy(req_srv.enc_token, res_tgt.enc_token, res_tgt.token_len);
    req_srv.token_len = res_tgt.token_len;
    
    // Interactive part: Let user pick whether to send correct or fake ID
    char auth_plain[32];
    char choice;
    printf("\n--- Intercept Option ---\n");
    printf("Do you want to send WRONG information (corrupt the ID) to test rejection? (y/n): ");
    scanf(" %c", &choice);
    
    if (choice == 'y' || choice == 'Y') {
        printf(">>> Tampering with Authenticator payload... Using fake ID 'HACKER'.\n");
        sprintf(auth_plain, "HACKER,%d", 1234567); 
    } else {
        printf(">>> Using correct ID.\n");
        sprintf(auth_plain, "%s,%d", req_tgt.client_id, 1234567); // "Arnav,1234567"
    }
    
    int auth_len = strlen(auth_plain) + 1; // including null terminator
    
    printf("\n[STEP 3] Preparing to send Service Request to Server...\n");
    printf("[CRYPTO] Encrypting the Authenticator payload ('%s') using the short-term Session Key (0x%03X).\n", auth_plain, session_key);
    printf("         -> Algorithm: SDES (Simplified DES) mode ECB.\n");
    
    // SDES ECB Encrypt Authenticator
    encrypt_ecb((uint8_t*)auth_plain, auth_len, session_key, req_srv.enc_authenticator);
    req_srv.auth_len = auth_len;
    
    printf("         -> Sending Unaltered Encrypted Token + Newly Encrypted Authenticator to Server.\n");
    send(sock, (char*)&req_srv, sizeof(MsgReqSrv), 0);
    
    // --- STEP 4: Receive Service Response ---
    MsgResSrv res_srv;
    recv(sock, (char*)&res_srv, sizeof(MsgResSrv), 0);
    
    printf("\n[STEP 4] Received final verdict from Service Server:\n");
    if (res_srv.type == MSG_RES_SRV) {
        if (res_srv.status == 1) {
            printf("         => ACCESS GRANTED: Server successfully verified Token and Authenticator match!\n");
        } else {
            printf("         => ACCESS DENIED: Server detected ID mismatch or Invalid Crypto!\n");
        }
    }

    printf("\nClient shutting down...\n");
    closesocket(sock);
    WSACleanup();
    return 0;
}
