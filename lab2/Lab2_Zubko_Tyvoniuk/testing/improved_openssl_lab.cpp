#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <numeric>
#include <cmath>

// Функція для виведення масиву байтів у hex форматі
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

// Функція для базового статистичного аналізу випадкових даних
void analyze_randomness(const unsigned char* data, size_t len) {
    std::cout << "\n--- Статистичний аналіз випадковості ---" << std::endl;

    // Підрахунок частоти кожного байта (0-255)
    std::vector<int> frequency(256, 0);
    for (size_t i = 0; i < len; i++) {
        frequency[data[i]]++;
    }

    // Очікувана частота для рівномірного розподілу
    double expected = (double)len / 256.0;
    std::cout << "Очікувана частота для кожного значення: " << expected << std::endl;

    // Обчислення хі-квадрат статистики
    double chi_square = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = frequency[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    std::cout << "Хі-квадрат статистика: " << chi_square << std::endl;
    std::cout << "Критичне значення (α=0.05, df=255): 293.25" << std::endl;

    if (chi_square < 293.25) {
        std::cout << "Результат: Послідовність ВІДПОВІДАЄ критеріям рівномірного розподілу" << std::endl;
    } else {
        std::cout << "Результат: Послідовність НЕ відповідає критеріям рівномірного розподілу" << std::endl;
    }

    // Підрахунок ентропії Шеннона
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / len;
            entropy -= p * log2(p);
        }
    }
    std::cout << "Ентропія Шеннона: " << entropy << " біт/байт (ідеал: 8.0)" << std::endl;

    // Перевірка на повторювані послідовності (прості повтори)
    int repeats = 0;
    for (size_t i = 1; i < len; i++) {
        if (data[i] == data[i-1]) {
            repeats++;
        }
    }
    double repeat_ratio = (double)repeats / (len - 1) * 100;
    std::cout << "Відсоток послідовних повторів: " << repeat_ratio << "% (очікується ~0.4%)" << std::endl;
}

// 1. Аналіз функції генерації ПВП
void test_rand_bytes() {
    std::cout << "\n=== 1. Аналіз функції генерації ПВП (RAND_bytes) ===" << std::endl;

    // Тест 1: Генерація 4096 байт
    const size_t buffer_size = 4096;
    unsigned char buffer[buffer_size];

    std::cout << "\nВиклик RAND_bytes(" << buffer_size << " байт)..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    int ret = RAND_bytes(buffer, buffer_size);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;

    std::cout << "Код повернення: " << ret << (ret == 1 ? " (Успіх)" : " (Помилка)") << std::endl;
    std::cout << "Час генерації: " << duration.count() << " мс" << std::endl;

    if (ret == 1) {
        std::cout << "\nПерші 48 байт згенерованої послідовності: ";
        print_hex(buffer, 48);

        // Статистичний аналіз
        analyze_randomness(buffer, buffer_size);
    } else {
        std::cerr << "Помилка генерації випадкових байтів!" << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // Тест 2: Множинна генерація для перевірки унікальності
    std::cout << "\n--- Тест унікальності: генерація 10 послідовностей по 32 байти ---" << std::endl;
    bool all_unique = true;
    unsigned char sequences[10][32];

    for (int i = 0; i < 10; i++) {
        RAND_bytes(sequences[i], 32);
        std::cout << "Послідовність " << (i+1) << ": ";
        print_hex(sequences[i], 16);

        // Перевірка на дублікати з попередніми
        for (int j = 0; j < i; j++) {
            if (memcmp(sequences[i], sequences[j], 32) == 0) {
                all_unique = false;
                std::cout << "ПОПЕРЕДЖЕННЯ: Знайдено дублікат з послідовністю " << (j+1) << std::endl;
            }
        }
    }

    if (all_unique) {
        std::cout << "Результат: Усі послідовності унікальні ✓" << std::endl;
    }
}

// 2. Аналіз функції генерації ключів RSA з множинними вимірюваннями
void test_rsa_generate() {
    std::cout << "\n=== 2. Аналіз функції генерації ключів RSA ===" << std::endl;

    int key_lengths[] = {1024, 2048, 4096};
    const int num_runs = 5; // Кількість запусків для кожної довжини

    std::cout << "\nКожна довжина ключа тестується " << num_runs << " разів для точності вимірювань.\n" << std::endl;

    for (int bits : key_lengths) {
        std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║  Генерація RSA ключа довжиною " << bits << " біт" << std::string(bits == 1024 ? 17 : bits == 2048 ? 17 : 17, ' ') << "║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;

        std::vector<double> times;
        RSA* last_key = nullptr;

        for (int run = 1; run <= num_runs; run++) {
            auto start = std::chrono::high_resolution_clock::now();

            RSA* rsa_key = RSA_new();
            BIGNUM* bne = BN_new();

            if (!rsa_key || !bne) {
                std::cerr << "Помилка створення структур RSA/BIGNUM!" << std::endl;
                continue;
            }

            BN_set_word(bne, RSA_F4); // 65537

            int ret = RSA_generate_key_ex(rsa_key, bits, bne, NULL);

            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> duration = end - start;

            if (ret == 1) {
                times.push_back(duration.count());
                std::cout << "  Запуск " << run << ": " << std::fixed << std::setprecision(6) 
                         << duration.count() << " с" << std::endl;

                // Зберігаємо останній ключ для виведення
                if (run == num_runs) {
                    last_key = rsa_key;
                } else {
                    RSA_free(rsa_key);
                }
            } else {
                std::cerr << "Помилка генерації ключа!" << std::endl;
                ERR_print_errors_fp(stderr);
                RSA_free(rsa_key);
            }

            BN_free(bne);
        }

        // Обчислення статистики
        if (!times.empty()) {
            double mean = std::accumulate(times.begin(), times.end(), 0.0) / times.size();

            double variance = 0.0;
            for (double t : times) {
                variance += (t - mean) * (t - mean);
            }
            variance /= times.size();
            double stddev = sqrt(variance);

            double min_time = *std::min_element(times.begin(), times.end());
            double max_time = *std::max_element(times.begin(), times.end());

            std::cout << "\n--- Статистика ---" << std::endl;
            std::cout << "Середній час: " << mean << " с" << std::endl;
            std::cout << "Стандартне відхилення: " << stddev << " с" << std::endl;
            std::cout << "Мінімальний час: " << min_time << " с" << std::endl;
            std::cout << "Максимальний час: " << max_time << " с" << std::endl;
            std::cout << "Коефіцієнт варіації: " << (stddev / mean * 100) << "%" << std::endl;
        }

        // Виведення структури ключа
        if (last_key) {
            std::cout << "\n--- Структура згенерованого ключа ---" << std::endl;

            // Публічний ключ
            BIO* bio_pub = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(bio_pub, last_key);

            char* pub_key_data;
            long pub_key_len = BIO_get_mem_data(bio_pub, &pub_key_data);

            std::cout << "Публічний ключ (формат PEM):" << std::endl;
            std::cout << std::string(pub_key_data, pub_key_len) << std::endl;

            BIO_free(bio_pub);

            // Приватний ключ (перші 200 символів)
            BIO* bio_priv = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPrivateKey(bio_priv, last_key, NULL, NULL, 0, NULL, NULL);

            char* priv_key_data;
            long priv_key_len = BIO_get_mem_data(bio_priv, &priv_key_data);

            std::cout << "Приватний ключ (перші 200 символів):" << std::endl;
            std::cout << std::string(priv_key_data, std::min(200L, priv_key_len)) << "..." << std::endl;

            BIO_free(bio_priv);

            RSA_free(last_key);
        }
    }
}

int main() {
    std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Лабораторна робота №2                                       ║" << std::endl;
    std::cout << "║  Реалізація алгоритмів генерації ключів криптосистем        ║" << std::endl;
    std::cout << "║  Бібліотека: OpenSSL                                         ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;

    // Перевірка доступності ГПВП
    if (RAND_status() == 1) {
        std::cout << "\n✓ Генератор псевдовипадкових чисел ініціалізовано успішно" << std::endl;
    } else {
        std::cout << "\n✗ ПОПЕРЕДЖЕННЯ: Недостатньо ентропії для ГПВП!" << std::endl;
    }

    test_rand_bytes();
    test_rsa_generate();

    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Програма завершила роботу успішно                          ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;

    return 0;
}
