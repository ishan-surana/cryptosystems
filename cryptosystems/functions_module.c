#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #define EXPORT __declspec(dllexport)
    typedef NTSTATUS(WINAPI* BCryptGenRandom_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);
    #ifndef STATUS_SUCCESS
        #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
    #endif
#else
    #include <fcntl.h>
    #include <unistd.h>
    #define EXPORT __attribute__((visibility("default")))
#endif

// Cross-platform random byte generator
EXPORT unsigned char* generate_random_sequence(size_t bits) {
    size_t byte_count = (bits + 7) / 8;
    unsigned char *buffer = (unsigned char*)malloc(byte_count);
    if (!buffer) return NULL;

#ifdef _WIN32
    HMODULE hBcrypt = LoadLibrary("bcrypt.dll");
    if (!hBcrypt) {
        free(buffer);
        return NULL;
    }

    BCryptGenRandom_t pBCryptGenRandom = (BCryptGenRandom_t)GetProcAddress(hBcrypt, "BCryptGenRandom");
    if (!pBCryptGenRandom) {
        FreeLibrary(hBcrypt);
        free(buffer);
        return NULL;
    }

    if (pBCryptGenRandom(NULL, buffer, (ULONG)byte_count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        FreeLibrary(hBcrypt);
        free(buffer);
        return NULL;
    }
    FreeLibrary(hBcrypt);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1 || read(fd, buffer, byte_count) != (ssize_t)byte_count) {
        free(buffer);
        close(fd);
        return NULL;
    }
    close(fd);
#endif

    return buffer;
}

// Generate a random N-bit integer with GMP
EXPORT void getRandomInteger(mpz_t result, int N) {
    size_t byte_count = (N + 7) / 8;
    unsigned char *random_bytes = generate_random_sequence(N);
    if (!random_bytes) {
        fprintf(stderr, "Failed to allocate memory for random bytes\n");
        exit(EXIT_FAILURE);
    }

    mpz_import(result, byte_count, 1, sizeof(random_bytes[0]), 0, 0, random_bytes);
    if(mpz_sizeinbase(result, 2) > N) mpz_fdiv_q_2exp(result, result, mpz_sizeinbase(result, 2) - N);
    mpz_setbit(result, N - 1);
    free(random_bytes);
}

EXPORT void getRandomRange(mpz_t result, const mpz_t a, const mpz_t b) {
    mpz_t range_size;
    mpz_init(range_size);

    mpz_sub(range_size, b, a);
    if (mpz_cmp_ui(range_size, 0) == 0) {
        mpz_set(result, a);
        mpz_clear(range_size);
        return;
    }

    int bits = mpz_sizeinbase(range_size, 2);
    do {
        do bits = rand() % bits + 1; while (bits == 0);
        getRandomInteger(result, bits);
    } while (mpz_cmp(result, range_size) >= 0);

    mpz_add(result, a, result);
    mpz_clear(range_size);
}

// Check if a number is prime using GMP's built-in function
EXPORT int isPrime(const mpz_t N, int k) {
    return mpz_probab_prime_p(N, k) > 0;
}

// Generate a random N-bit prime number
EXPORT void getPrime(mpz_t result, int N) {
    if (N < 2) {
        fprintf(stderr, "N should be >= 2\n");
        exit(EXIT_FAILURE);
    }
    do {
        getRandomInteger(result, N);
    } while (!isPrime(result, 10));
}

// Function to check if g is a valid generator for p (checks all divisors of p-1)
int is_valid_generator(mpz_t g, mpz_t p) {
    mpz_t result;
    mpz_init(result);

    // g^((p-1)/2) mod p
    mpz_sub_ui(result, p, 1);
    mpz_fdiv_q_2exp(result, result, 1);
    mpz_powm(result, g, result, p);
    int valid = mpz_cmp_ui(result, 1) != 0; // If g^((p-1)/2) == 1 mod p, then g is a valid generator
    
    mpz_clear(result);
    return valid;
}

// Function to find the smallest generator for a prime number p
EXPORT void find_generator(mpz_t p, mpz_t g) {
    mpz_t candidate;
    mpz_init(candidate);
    mpz_set_ui(candidate, 2);

    while (mpz_cmp(candidate, p) < 0) {
        if (isPrime(candidate, 10) && is_valid_generator(candidate, p)) {
            mpz_set(g, candidate);
            break;
        }
        mpz_add_ui(candidate, candidate, 1);
    }

    mpz_clear(candidate);
}

EXPORT int export_integer(const mpz_t value, unsigned char **out_buffer, size_t *out_size) {
    *out_size = (mpz_sizeinbase(value, 2) + 7) / 8;
    *out_buffer = (unsigned char *)malloc(*out_size);
    if (!*out_buffer) return -1;
    mpz_export(*out_buffer, out_size, 1, 1, 1, 0, value);
    return 0;
}

EXPORT void import_integer(mpz_t result, const unsigned char *buffer, size_t size) {
    mpz_import(result, size, 1, 1, 1, 0, buffer);
}
