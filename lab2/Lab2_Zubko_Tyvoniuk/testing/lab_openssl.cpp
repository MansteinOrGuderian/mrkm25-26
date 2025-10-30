#include <iostream>
#include <vector>
#include <iomanip>
#include <chrono>
#include <numeric>
#include <cmath>
#include <map>
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

// 1. Тестування якості випадковості RAND_bytes
void test_randomness() {
    std::cout << "--- 1. Тестування якості випадковості RAND_bytes ---" << std::endl;
    const int TEST_SIZE = 20000; // 160,000 біт для тестів
    std::vector<unsigned char> data(TEST_SIZE);
    if (RAND_bytes(data.data(), TEST_SIZE) != 1) {
        std::cerr << "Помилка генерації ПВП!" << std::endl;
        return;
    }

    // 1.1 Тест на рівномірність розподілу байтів
    std::cout << "\n1.1. Тест на рівномірність розподілу байтів" << std::endl;
    std::map<int, int> counts;
    for(int i = 0; i < 256; ++i) counts[i] = 0;
    for(unsigned char byte : data) {
        counts[byte]++;
    }
    double expected = static_cast<double>(TEST_SIZE) / 256.0;
    double chi_squared = 0;
    for(int i = 0; i < 256; ++i) {
        chi_squared += std::pow(counts[i] - expected, 2) / expected;
    }
    std::cout << "Очікувана частота для кожного байта: " << expected << std::endl;
    std::cout << "Статистика Хі-квадрат: " << chi_squared << " (для 255 ступенів свободи, очікується ~255)" << std::endl;
    if (chi_squared > 200 && chi_squared < 310) { // Приблизний діапазон для p-value > 0.01
        std::cout << "Результат: Розподіл виглядає рівномірним (ТЕСТ ПРОЙДЕНО)." << std::endl;
    } else {
        std::cout << "Результат: Розподіл нерівномірний (ТЕСТ ПРОВАЛЕНО)." << std::endl;
    }
    
    // 1.2 Тест на повторювані патерни (на прикладі пар байтів)
    std::cout << "\n1.2. Базовий тест на повторювані патерни (диграми)" << std::endl;
    std::map<int, int> digram_counts;
    for(size_t i = 0; i < TEST_SIZE - 1; ++i) {
        int digram = (data[i] << 8) | data[i+1];
        digram_counts[digram]++;
    }
    int max_count = 0;
    for(auto const& [key, val] : digram_counts) {
        if(val > max_count) max_count = val;
    }
    std::cout << "Максимальна частота повторення пари байтів: " << max_count << std::endl;
    if (max_count < 10) { // Емпіричний поріг для невеликого тесту
        std::cout << "Результат: Очевидні патерни не виявлено (ТЕСТ ПРОЙДЕНО)." << std::endl;
    } else {
        std::cout << "Результат: Виявлено часті патерни (ТЕСТ ПРОВАЛЕНО)." << std::endl;
    }
}


// 2. Порівняння продуктивності генерації ключів RSA
void test_rsa_performance() {
    std::cout << "\n--- 2. Порівняння продуктивності генерації ключів RSA ---" << std::endl;
    
    int key_lengths[] = {1024, 2048, 4096};
    const int RUNS = 10; // Кількість запусків для кожної довжини

    for (int bits : key_lengths) {
        std::cout << "\n--- Тестування ключа " << bits << " біт (" << RUNS << " запусків) ---" << std::endl;
        std::vector<double> durations;
        
        for (int i = 0; i < RUNS; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            
            RSA* rsa_key = RSA_new();
            BIGNUM* bne = BN_new();
            BN_set_word(bne, RSA_F4);
            RSA_generate_key_ex(rsa_key, bits, bne, NULL);
            
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> duration = end - start;
            durations.push_back(duration.count());

            RSA_free(rsa_key);
            BN_free(bne);
        }
        
        double sum = std::accumulate(durations.begin(), durations.end(), 0.0);
        double mean = sum / durations.size();
        
        double sq_sum = 0.0;
        for(const auto& d : durations) {
            sq_sum += (d - mean) * (d - mean);
        }
        double stdev = std::sqrt(sq_sum / durations.size());

        std::cout << "Середній час генерації: " << mean << " с" << std::endl;
        std::cout << "Стандартне відхилення: " << stdev << " с" << std::endl;
        
        if (RUNS == 10 && bits == 2048) {
            std::cout << "\nПриклад згенерованого ключа (2048 біт):" << std::endl;
            RSA* rsa_key = RSA_new();
            BIGNUM* bne = BN_new();
            BN_set_word(bne, RSA_F4);
            RSA_generate_key_ex(rsa_key, bits, bne, NULL);
            
            BIO* bio_public = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(bio_public, rsa_key);
            
            char* public_key_str;
            BIO_get_mem_data(bio_public, &public_key_str);
            std::cout << public_key_str << std::endl;

            BIO_free_all(bio_public);
            RSA_free(rsa_key);
            BN_free(bne);
        }
    }
}


int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    test_randomness();
    test_rsa_performance();

    return 0;
}