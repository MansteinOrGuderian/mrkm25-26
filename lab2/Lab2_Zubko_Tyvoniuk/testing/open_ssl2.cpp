#include <iostream>
#include <vector>
#include <iomanip>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <windows.h> // Потрібно для SetConsoleOutputCP

// Функція для виводу байтів у шістнадцятковому форматі
void print_hex(const unsigned char* data, size_t len) {
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::setw(2) << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

// 1. Аналіз функції генерації ПВП (RAND_bytes)
void test_rand_bytes() {
    std::cout << "--- 1. Аналіз функції генерації ПВП (RAND_bytes) ---" << std::endl;
    
    const int buffer_size = 4096;
    std::vector<unsigned char> buffer(buffer_size);

    int ret = RAND_bytes(buffer.data(), buffer_size);

    std::cout << "Виклик RAND_bytes(" << buffer_size << ")..." << std::endl;
    if (ret == 1) {
        std::cout << "Код повернення: " << ret << " (Успіх)" << std::endl;
        std::cout << "Згенерована послідовність (4096 байт): ";
        print_hex(buffer.data(), buffer_size);
    } else {
        std::cerr << "Помилка генерації випадкових байтів! Код: " << ret << std::endl;
    }
}

// 2. Аналіз функції генерації ключів RSA
void test_rsa_generate() {
    std::cout << "\n--- 2. Аналіз функції генерації ключів RSA ---" << std::endl;

    int key_lengths[] = {1024, 2048, 4096};

    for (int bits : key_lengths) {
        std::cout << "\n--- Генерація RSA ключа довжиною " << bits << " біт ---" << std::endl;

        auto start = std::chrono::high_resolution_clock::now();
        
        RSA* rsa_key = RSA_new();
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4); 

        int ret = RSA_generate_key_ex(rsa_key, bits, bne, NULL);
        
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - start;

        if (ret == 1) {
            std::cout << "Код повернення: " << ret << " (Успіх)" << std::endl;
            std::cout << "Час генерації: " << duration.count() << " с" << std::endl;
            
            BIO* bio_private = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPrivateKey(bio_private, rsa_key, NULL, NULL, 0, NULL, NULL);

            BIO* bio_public = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(bio_public, rsa_key);
            
            char* private_key_str;
            long private_len = BIO_get_mem_data(bio_private, &private_key_str);
            char* public_key_str;
            long public_len = BIO_get_mem_data(bio_public, &public_key_str);

            std::cout << "\nПублічний ключ (формат PEM):" << std::endl;
            std::cout.write(public_key_str, public_len);

            std::cout << "\nПриватний ключ (перші 120 символів):" << std::endl;
            std::cout.write(private_key_str, 120) << "..." << std::endl;

            BIO_free_all(bio_private);
            BIO_free_all(bio_public);
        } else {
            std::cerr << "Помилка генерації RSA ключа! Код: " << ret << std::endl;
        }

        RSA_free(rsa_key);
        BN_free(bne);
    }
}

int main() {
    // --- FIX FOR ENCODING ---
    // Set both the console output and input to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    // ----------------------

    test_rand_bytes();
    test_rsa_generate();
    return 0;
}