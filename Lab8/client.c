#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <time.h>
#include "ecc.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

// Brute-force discrete log for small messages
// Finds m such that m*G = target
int discreteLog(Point target) {
    if (target.is_infinity) return 0;
    Point current = G;
    int m = 1;
    while (!current.is_infinity) {
        if (current.x == target.x && current.y == target.y) {
            return m;
        }
        current = pointAdd(current, G);
        m++;
        if (m > P + 100) { // Safety limit, N is roughly near P
            break;
        }
    }
    return -1; // Not found
}

int main() {
    srand(time(NULL));

    // KEY GENERATION
    int private_key = 10 + (rand() % 50); // d
    Point public_key = scalarMult(private_key, G); // Q = dG
    
    printf("--- Client Keys ---\n");
    printf("Private Key d: %d\n", private_key);
    printPoint(public_key, "Public Key Q");

    // INPUT MESSAGES
    int m1, m2;
    printf("\nEnter two small integer messages (m1, m2 >= 0 and m1+m2 < 50): ");
    scanf("%d %d", &m1, &m2);

    // ENCRYPTION
    printf("\n--- Encrypting messages (Detailed Steps) ---\n");
    printf("Step 1: Map the integer messages into points on the elliptic curve.\n");
    printf("        We do this by computing M = m * G (scalar multiplication).\n");
    Point M1 = scalarMult(m1, G);
    Point M2 = scalarMult(m2, G);
    printPoint(M1, "        Mapped Message Point M1 (m1 * G)");
    printPoint(M2, "        Mapped Message Point M2 (m2 * G)");

    printf("\nStep 2: Choose random ephemeral keys (k1, k2) for each encryption.\n");
    int k1 = 5 + (rand() % 20);
    int k2 = 5 + (rand() % 20);
    printf("        Chosen random k1: %d, k2: %d\n", k1, k2);

    Ciphertext C1, C2;
    
    printf("\nStep 3: Encrypt the first message (M1) using ElGamal on ECC.\n");
    printf("        Compute C1.C1 = k1 * G (Masking key component)\n");
    C1.C1 = scalarMult(k1, G);
    
    printf("        Compute the shared secret component S1 = k1 * Q (where Q is the public key)\n");
    Point S1 = scalarMult(k1, public_key);
    printPoint(S1, "        Shared secret S1");
    
    printf("        Compute C1.C2 = M1 + S1 (Adding the message to the shared secret)\n");
    C1.C2 = pointAdd(M1, S1);
    
    printf("\nStep 4: Encrypt the second message (M2) using ElGamal on ECC.\n");
    printf("        Compute C2.C1 = k2 * G (Masking key component)\n");
    C2.C1 = scalarMult(k2, G);
    
    printf("        Compute the shared secret component S2 = k2 * Q\n");
    Point S2 = scalarMult(k2, public_key);
    printPoint(S2, "        Shared secret S2");
    
    printf("        Compute C2.C2 = M2 + S2 (Adding the message to the shared secret)\n");
    C2.C2 = pointAdd(M2, S2);

    printf("\n--- Final Ciphertexts ---\n");
    printf("Ciphertext 1 (C1, C2):\n");
    printPoint(C1.C1, "  C1.C1");
    printPoint(C1.C2, "  C1.C2");
    
    printf("Ciphertext 2 (C1, C2):\n");
    printPoint(C2.C1, "  C2.C1");
    printPoint(C2.C2, "  C2.C2");

    // NETWORK SETUP
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;

    printf("\nInitializing Winsock...\n");
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
    printf("Connected to server.\n");

    // SEND AND RECEIVE
    send(sock, (char*)&C1, sizeof(Ciphertext), 0);
    send(sock, (char*)&C2, sizeof(Ciphertext), 0);
    
    Ciphertext Cadd;
    recv(sock, (char*)&Cadd, sizeof(Ciphertext), 0);
    
    printf("\n--- Received Homomorphically Added Ciphertext from Server ---\n");
    printPoint(Cadd.C1, "Cadd.C1");
    printPoint(Cadd.C2, "Cadd.C2");

    // DECRYPTION
    printf("\n--- Decrypting Result ---\n");
    // M_add = Cadd.C2 - d * Cadd.C1
    Point dCadd1 = scalarMult(private_key, Cadd.C1);
    Point Madd = pointAdd(Cadd.C2, pointNeg(dCadd1));
    printPoint(Madd, "Decrypted Point Madd");

    // BRUTE FORCE DISCRETE LOG
    int sum = discreteLog(Madd);
    if (sum != -1) {
        printf("\nRecovered plaintext sum: %d\n", sum);
    } else {
        printf("\nFailed to recover plaintext (discrete log not found in range).\n");
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
