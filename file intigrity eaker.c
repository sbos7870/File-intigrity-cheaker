#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h> // Requires OpenSSL library

#define BUFFER_SIZE 4096
#define HASH_LENGTH SHA256_DIGEST_LENGTH * 2 + 1 // Length of hex-encoded SHA256

char* calculate_sha256(const char* filepath) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return NULL; // File not found or error opening file
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    char* hexHash = malloc(HASH_LENGTH);
    if (!hexHash) {
        return NULL; // Memory allocation failed
    }

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hexHash[i * 2], "%02x", hash[i]);
    }
    hexHash[HASH_LENGTH - 1] = '\0'; // Null-terminate the string

    return hexHash;
}

int generate_and_save_hashes(const char* directory, const char* output_file) {
    FILE* outFile = fopen(output_file, "w");
    if (!outFile) {
        return 1; // Error opening output file
    }

    DIR* dir = opendir(directory);
    if (!dir) {
        fclose(outFile);
        return 1; // Error opening directory
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // Regular file
            char filepath[1024]; // Adjust size as needed
            snprintf(filepath, sizeof(filepath), "%s/%s", directory, entry->d_name);

            char* hash = calculate_sha256(filepath);
            if (hash) {
                fprintf(outFile, "%s:%s\n", filepath, hash);
                free(hash); // Free allocated memory
            } else {
                fprintf(stderr, "Error calculating hash for: %s\n", filepath);
            }
        }
    }

    closedir(dir);
    fclose(outFile);
    return 0; // Success
}

int verify_hashes_from_file(const char* directory, const char* hash_file) {
    FILE* inFile = fopen(hash_file, "r");
    if (!inFile) {
        return 1; // Error opening hash file
    }

    char line[2048]; // Adjust size as needed
    while (fgets(line, sizeof(line), inFile)) {
        line[strcspn(line, "\n")] = 0; // Remove newline

        char* filepath = strtok(line, ":");
        char* expectedHash = strtok(NULL, ":");

        if (filepath && expectedHash) {
            char fullPath[1024];
            snprintf(fullPath, sizeof(fullPath), "%s/%s", directory, strrchr(filepath, '/') + 1); // Extract filename

            char* calculatedHash = calculate_sha256(fullPath);
            if (calculatedHash) {
                if (strcmp(calculatedHash, expectedHash) == 0) {
                    printf("%s: Hashes match\n", fullPath);
                } else {
                    printf("%s: Hashes do not match\n", fullPath);
                }
                free(calculatedHash);
            } else {
                printf("%s: File not found or error\n", fullPath);
            }
        } else {
            fprintf(stderr, "Invalid hash file format\n");
        }
    }

    fclose(inFile);
    return 0; // Success
}

int main() {
    const char* directory = "."; // Current directory
    const char* hash_file = "file_hashes.txt";

    if (generate_and_save_hashes(directory, hash_file) == 0) {
        printf("Hashes generated and saved to %s\n", hash_file);
        verify_hashes_from_file(directory, hash_file);
    } else {
        fprintf(stderr, "Error generating hashes\n");
        return 1; // Error
    }

    return 0;
}
