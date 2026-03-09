// ============================================================
// CLIENT.C - S-DES Client (Windows / Winsock)
// Compile: gcc client.c -o client -lws2_32
// Run: client.exe
// ============================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024
#define KEY_SIZE 10

// ================= PERMUTATION TABLES =================
int IP_table[8]     = {2,6,3,1,4,8,5,7};
int IP_inv_table[8] = {4,1,3,5,7,2,8,6};
int EP_table[8]     = {4,1,2,3,2,3,4,1};
int P4_table[4]     = {2,4,3,1};
int P10_table[10]   = {3,5,2,7,4,10,1,9,8,6};
int P8_table[8]     = {6,3,7,4,8,5,10,9};

int S0[4][4] = {
    {1,0,3,2},
    {3,2,1,0},
    {0,2,1,3},
    {3,1,3,2}
};

int S1[4][4] = {
    {0,1,2,3},
    {2,0,1,3},
    {3,0,1,0},
    {2,1,0,3}
};

// ================= UTILITY FUNCTIONS =================
void permute(int *in, int *out, int *table, int size) {
    for(int i=0;i<size;i++)
        out[i] = in[table[i]-1];
}

void xor_bits(int *a, int *b, int *out, int n) {
    for(int i=0;i<n;i++)
        out[i] = a[i] ^ b[i];
}

void left_shift(int *bits, int n, int shifts) {
    int temp[n];
    for(int i=0;i<n;i++)
        temp[i] = bits[(i+shifts)%n];
    for(int i=0;i<n;i++)
        bits[i] = temp[i];
}

void print_binary(int *binary, int length) {
    for (int i = 0; i < length; i++) {
        printf("%d", binary[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
}

// ================= KEY GENERATION =================
void generate_keys(int *key, int *K1, int *K2) {
    int perm[10];
    permute(key, perm, P10_table, 10);

    int L[5], R[5];
    for(int i=0;i<5;i++){ L[i]=perm[i]; R[i]=perm[i+5]; }

    left_shift(L,5,1);
    left_shift(R,5,1);

    int comb[10];
    for(int i=0;i<5;i++){ comb[i]=L[i]; comb[i+5]=R[i]; }
    permute(comb, K1, P8_table, 8);

    left_shift(L,5,2);
    left_shift(R,5,2);
    for(int i=0;i<5;i++){ comb[i]=L[i]; comb[i+5]=R[i]; }
    permute(comb, K2, P8_table, 8);
}

// ================= F FUNCTION =================
void f_function(int *right, int *key, int *output) {
    printf("    F-function input (4 bits): ");
    print_binary(right, 4);
    
    int expanded[8];
    permute(right, expanded, EP_table, 8);
    printf("    After E/P expansion (8 bits): ");
    print_binary(expanded, 8);
    
    printf("    Subkey: ");
    print_binary(key, 8);
    
    int xored[8];
    xor_bits(expanded, key, xored, 8);
    printf("    After XOR with key: ");
    print_binary(xored, 8);
    
    // S-box substitution
    int row0 = (xored[0] << 1) | xored[3];
    int col0 = (xored[1] << 1) | xored[2];
    int row1 = (xored[4] << 1) | xored[7];
    int col1 = (xored[5] << 1) | xored[6];
    
    int s0_output = S0[row0][col0];
    int s1_output = S1[row1][col1];
    
    printf("    S0[%d][%d] = %d, S1[%d][%d] = %d\n", row0, col0, s0_output, row1, col1, s1_output);
    
    int sbox_output[4];
    sbox_output[0] = (s0_output >> 1) & 1;
    sbox_output[1] = s0_output & 1;
    sbox_output[2] = (s1_output >> 1) & 1;
    sbox_output[3] = s1_output & 1;
    
    printf("    After S-boxes (4 bits): ");
    print_binary(sbox_output, 4);
    
    permute(sbox_output, output, P4_table, 4);
    printf("    After P4 permutation: ");
    print_binary(output, 4);
}

// ================= S-DES =================
void sdes_crypt(int *input, int *output, int *K1, int *K2, int encrypt) {
    printf("\n  %s Steps:\n", encrypt ? "ENCRYPTION" : "DECRYPTION");
    printf("  Input: ");
    print_binary(input, 8);
    
    int ip_output[8];
    permute(input, ip_output, IP_table, 8);
    printf("  After Initial Permutation (IP): ");
    print_binary(ip_output, 8);
    
    int left[4], right[4];
    for (int i = 0; i < 4; i++) {
        left[i] = ip_output[i];
        right[i] = ip_output[i + 4];
    }
    printf("  Split - Left: ");
    print_binary(left, 4);
    printf("         Right: ");
    print_binary(right, 4);
    
    // Round 1
    printf("\n  === Round 1 ===\n");
    int f_output[4];
    f_function(right, encrypt ? K1 : K2, f_output);
    
    printf("    Left before XOR: ");
    print_binary(left, 4);
    printf("    F-function output: ");
    print_binary(f_output, 4);
    
    int new_left[4];
    xor_bits(left, f_output, new_left, 4);
    printf("    New Left (after XOR): ");
    print_binary(new_left, 4);
    
    // Swap
    printf("  After Swap - Left: ");
    print_binary(right, 4);
    printf("              Right: ");
    print_binary(new_left, 4);
    
    for (int i = 0; i < 4; i++) {
        left[i] = right[i];
        right[i] = new_left[i];
    }
    
    // Round 2
    printf("\n  === Round 2 ===\n");
    f_function(right, encrypt ? K2 : K1, f_output);
    
    printf("    Left before XOR: ");
    print_binary(left, 4);
    printf("    F-function output: ");
    print_binary(f_output, 4);
    
    xor_bits(left, f_output, new_left, 4);
    printf("    New Left (after XOR): ");
    print_binary(new_left, 4);
    
    // Combine without swap
    int pre_inv[8];
    for (int i = 0; i < 4; i++) {
        pre_inv[i] = new_left[i];
        pre_inv[i + 4] = right[i];
    }
    printf("  Before Inverse IP: ");
    print_binary(pre_inv, 8);
    
    permute(pre_inv, output, IP_inv_table, 8);
    printf("  After Inverse IP (Output): ");
    print_binary(output, 8);
}

// ================= MAIN =================
int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock;
    struct sockaddr_in server;
    char plaintext[100], buffer[BUFFER_SIZE]={0};

    printf("Enter plaintext: ");
    fgets(plaintext,sizeof(plaintext),stdin);
    plaintext[strcspn(plaintext,"\n")] = 0;

    int len = strlen(plaintext);
    int *bin = malloc(len*8*sizeof(int));

    for(int i=0;i<len;i++)
        for(int j=0;j<8;j++)
            bin[i*8+j] = (plaintext[i]>>(7-j)) & 1;

    int key[KEY_SIZE] = {1,0,1,0,0,0,0,0,1,0};
    int K1[8], K2[8];
    generate_keys(key,K1,K2);

    int *enc = malloc(len*8*sizeof(int));
    printf("\n\n========================================\n");
    printf("=== ENCRYPTION PROCESS ===\n");
    printf("========================================\n");
    for(int i=0;i<len;i++) {
        printf("\n--- Processing Character '%c' (Block %d) ---\n", plaintext[i], i + 1);
        sdes_crypt(&bin[i*8], &enc[i*8], K1, K2, 1);
    }

    printf("\n\n=== FINAL CIPHERTEXT ===\n");
    printf("Binary: ");
    print_binary(enc, len*8);
    printf("\n");

    char cipher[len*8+1];
    for(int i=0;i<len*8;i++)
        cipher[i] = enc[i] + '0';
    cipher[len*8] = '\0';

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (struct sockaddr*)&server, sizeof(server));
    send(sock, cipher, strlen(cipher), 0);
    recv(sock, buffer, BUFFER_SIZE, 0);

    printf("Decrypted from server: %s\n", buffer);

    closesocket(sock);
    WSACleanup();
    return 0;
}
