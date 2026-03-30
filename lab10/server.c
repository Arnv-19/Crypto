#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include "common.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

// Modular exponentiation
long long modPow(long long base, long long exp, long long mod) {
    long long res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            res = (res * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, client_sock;
    struct sockaddr_in server, client;
    int c = sizeof(struct sockaddr_in);
    Payload payload;

    printf("Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code: %d\n", WSAGetLastError());
        return 1;
    }

    listen(server_fd, 3);
    
    printf("--- ElGamal Digital Signature (Verifier/Server) ---\n");
    printf("Waiting for incoming connections on port %d...\n", PORT);

    client_sock = accept(server_fd, (struct sockaddr *)&client, &c);
    if (client_sock == INVALID_SOCKET) {
        printf("accept failed\n");
        return 1;
    }
    printf("Client connected.\n");

    int read_size = recv(client_sock, (char*)&payload, sizeof(Payload), 0);
    if (read_size > 0) {
        long long p = payload.pub_key.p;
        long long g = payload.pub_key.g;
        long long y = payload.pub_key.y;
        long long r = payload.sig.r;
        long long s = payload.sig.s;
        long long m = payload.sig.m;

        printf("\nReceived Message: %lld\n", m);
        printf("Received Public Params (p=%lld, g=%lld, y=%lld)\n", p, g, y);
        printf("Received Signature (r=%lld, s=%lld)\n", r, s);

        // Verification: Check if 0 < r < p
        if (r <= 0 || r >= p) {
            printf("\n=> Verification FAILED: r must be 0 < r < p.\n");
        } else {
            // Compute v1 = (y^r * r^s) mod p
            // First decompose it to prevent overflow
            long long y_pow_r = modPow(y, r, p);
            long long r_pow_s = modPow(r, s, p);
            long long v1 = (y_pow_r * r_pow_s) % p;

            // Compute v2 = g^m mod p
            long long v2 = modPow(g, m, p);

            printf("\nCalculated v1 = (y^r * r^s) mod p = %lld\n", v1);
            printf("Calculated v2 = (g^m) mod p = %lld\n", v2);

            if (v1 == v2) {
                printf("=> Verification SUCCESS. The signature is valid.\n");
            } else {
                printf("=> Verification FAILED. The signature is invalid.\n");
            }
        }
    } else if(read_size == 0) {
        printf("Client disconnected before sending payload.\n");
    } else {
        printf("recv failed with error: %d\n", WSAGetLastError());
    }

    closesocket(client_sock);
    closesocket(server_fd);
    WSACleanup();

    return 0;
}
