#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 8
#define KEY_SIZE 10

// ============== PERMUTATION TABLES ==============
int IP_table[8] = {2, 6, 3, 1, 4, 8, 5, 7};
int IP_inv_table[8] = {4, 1, 3, 5, 7, 2, 8, 6};
int EP_table[8] = {4, 1, 2, 3, 2, 3, 4, 1};
int P4_table[4] = {2, 4, 3, 1};
int P10_table[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
int P8_table[8] = {6, 3, 7, 4, 8, 5, 10, 9};

// S-boxes
int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// ============== UTILITY FUNCTIONS ==============
void text_to_binary(char *text, int *binary, int length) {
    for (int i = 0; i < length; i++) {
        int ascii = (int)text[i];
        for (int j = 7; j >= 0; j--) {
            binary[i * 8 + (7 - j)] = (ascii >> j) & 1;
        }
    }
}

void binary_to_text(int *binary, char *text, int length) {
    for (int i = 0; i < length; i++) {
        int ascii = 0;
        for (int j = 0; j < 8; j++) {
            ascii = (ascii << 1) | binary[i * 8 + j];
        }
        text[i] = (char)ascii;
    }
    text[length] = '\0';
}

void print_binary(int *binary, int length) {
    for (int i = 0; i < length; i++) {
        printf("%d", binary[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    printf("\n");
}

void permute(int *input, int *output, int *table, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = input[table[i] - 1];
    }
}

void xor_bits(int *a, int *b, int *result, int length) {
    for (int i = 0; i < length; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void left_shift(int *bits, int size, int shifts) {
    int temp[size];
    for (int i = 0; i < size; i++) {
        temp[i] = bits[(i + shifts) % size];
    }
    for (int i = 0; i < size; i++) {
        bits[i] = temp[i];
    }
}

// ============== KEY GENERATION ==============
void generate_keys(int *key, int *K1, int *K2) {
    printf("\n--- KEY GENERATION STEPS ---\n");
    printf("Original Key: ");
    print_binary(key, 10);
    
    int permuted_key[10];
    permute(key, permuted_key, P10_table, 10);
    printf("After P10 permutation: ");
    print_binary(permuted_key, 10);
    
    int left[5], right[5];
    for (int i = 0; i < 5; i++) {
        left[i] = permuted_key[i];
        right[i] = permuted_key[i + 5];
    }
    printf("Split into Left: ");
    print_binary(left, 5);
    printf("           Right: ");
    print_binary(right, 5);
    
    // Generate K1
    printf("\n--- Generating K1 ---\n");
    left_shift(left, 5, 1);
    left_shift(right, 5, 1);
    printf("After LS-1 Left: ");
    print_binary(left, 5);
    printf("          Right: ");
    print_binary(right, 5);
    
    int combined[10];
    for (int i = 0; i < 5; i++) {
        combined[i] = left[i];
        combined[i + 5] = right[i];
    }
    printf("Combined: ");
    print_binary(combined, 10);
    
    permute(combined, K1, P8_table, 8);
    printf("K1 (after P8): ");
    print_binary(K1, 8);
    
    // Generate K2
    printf("\n--- Generating K2 ---\n");
    left_shift(left, 5, 2);
    left_shift(right, 5, 2);
    printf("After LS-2 Left: ");
    print_binary(left, 5);
    printf("          Right: ");
    print_binary(right, 5);
    
    for (int i = 0; i < 5; i++) {
        combined[i] = left[i];
        combined[i + 5] = right[i];
    }
    printf("Combined: ");
    print_binary(combined, 10);
    
    permute(combined, K2, P8_table, 8);
    printf("K2 (after P8): ");
    print_binary(K2, 8);
}

// ============== F FUNCTION ==============
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

// ============== ENCRYPTION/DECRYPTION ==============
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

// ============== MAIN FUNCTION ==============
int main() {
    char plaintext[100];
    int key[KEY_SIZE] = {1, 0, 1, 0, 0, 0, 0, 0, 1, 0}; // Default 10-bit key
    
    printf("=== Simplified DES (S-DES) ===\n\n");
    
    // Get input text
    printf("Enter plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = 0; // Remove newline
    
    int text_length = strlen(plaintext);
    int binary_length = text_length * 8;
    int *binary_text = (int*)malloc(binary_length * sizeof(int));
    
    // Convert text to binary
    text_to_binary(plaintext, binary_text, text_length);
    printf("\n=== TEXT TO BINARY CONVERSION ===\n");
    for (int i = 0; i < text_length; i++) {
        printf("Character '%c' (ASCII %d): ", plaintext[i], (int)plaintext[i]);
        print_binary(&binary_text[i * 8], 8);
    }
    
    // Generate subkeys
    int K1[8], K2[8];
    generate_keys(key, K1, K2);
    
    // Encrypt each 8-bit block
    int *ciphertext = (int*)malloc(binary_length * sizeof(int));
    printf("\n\n========================================\n");
    printf("=== ENCRYPTION PROCESS ===\n");
    printf("========================================\n");
    
    for (int i = 0; i < text_length; i++) {
        printf("\n--- Processing Character '%c' (Block %d) ---", plaintext[i], i + 1);
        sdes_crypt(&binary_text[i * 8], &ciphertext[i * 8], K1, K2, 1);
    }
    
    printf("\n\n=== FINAL CIPHERTEXT ===\n");
    printf("Binary: ");
    print_binary(ciphertext, binary_length);
    
    // Decrypt
    int *decrypted = (int*)malloc(binary_length * sizeof(int));
    printf("\n========================================\n");
    printf("=== DECRYPTION PROCESS ===\n");
    printf("========================================\n");
    
    for (int i = 0; i < text_length; i++) {
        printf("\n--- Processing Block %d ---", i + 1);
        sdes_crypt(&ciphertext[i * 8], &decrypted[i * 8], K1, K2, 0);
    }
    
    printf("Decrypted (binary):\n");
    print_binary(decrypted, binary_length);
    
    char decrypted_text[text_length + 1];
    binary_to_text(decrypted, decrypted_text, text_length);
    printf("Decrypted text: %s\n", decrypted_text);
    
    free(binary_text);
    free(ciphertext);
    free(decrypted);
    
    return 0;
}