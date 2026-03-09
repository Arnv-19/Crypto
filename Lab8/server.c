#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "ecc.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in server, client;
    int c;

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
    printf("Waiting for incoming connections...\n");

    c = sizeof(struct sockaddr_in);
    new_socket = accept(server_fd, (struct sockaddr *)&client, &c);
    if (new_socket == INVALID_SOCKET) {
        printf("Accept failed with error code: %d\n", WSAGetLastError());
        return 1;
    }
    printf("Connection accepted.\n");

    // Receive Ciphertexts
    Ciphertext C1, C2;
    int bytes_received = recv(new_socket, (char*)&C1, sizeof(Ciphertext), 0);
    if (bytes_received <= 0) {
        printf("Receive failed or client disconnected.\n");
        return 1;
    }
    recv(new_socket, (char*)&C2, sizeof(Ciphertext), 0);

    printf("\n--- Received Ciphertexts ---\n");
    printPoint(C1.C1, "C1.C1");
    printPoint(C1.C2, "C1.C2");
    printPoint(C2.C1, "C2.C1");
    printPoint(C2.C2, "C2.C2");

    // Homomorphic Addition
    Ciphertext Cadd;
    printf("\n--- Performing Homomorphic Addition ---\n");
    Cadd.C1 = pointAdd(C1.C1, C2.C1);
    Cadd.C2 = pointAdd(C1.C2, C2.C2);

    printPoint(Cadd.C1, "Cadd.C1");
    printPoint(Cadd.C2, "Cadd.C2");

    // Send back to client
    send(new_socket, (char*)&Cadd, sizeof(Ciphertext), 0);
    printf("\nSent homomorphically added ciphertext back to client.\n");

    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();

    return 0;
}
