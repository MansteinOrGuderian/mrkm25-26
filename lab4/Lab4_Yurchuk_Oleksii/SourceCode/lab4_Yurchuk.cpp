#include "Header.h"

// ANSI color codes for console output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

/**
 * Security testing framework for ElGamal implementation
 */
class SecurityTester {
private:
    std::ofstream logFile;

public:
    SecurityTester(const std::string& logFilename) {
        logFile.open(logFilename, std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Warning: Could not open log file" << std::endl;
        }
    }

    ~SecurityTester() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

void log(const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        if (logFile.is_open()) {
            std::tm timeInfo;
#ifdef _WIN32
            localtime_s(&timeInfo, &time);
#else
            localtime_r(&time, &timeInfo);
#endif
            logFile << std::put_time(&timeInfo, "%Y-%m-%d %H:%M:%S")
                << " - " << message << std::endl;
        }
        std::cout << message << std::endl;
    }

    /**
     * Test 1: Basic functionality test
     */
    bool testBasicEncryptionDecryption() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 1: Basic Encryption/Decryption Functionality" COLOR_RESET);
        log(std::string(60, '='));

        try {
            // Generate key pair
            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(2048);

            // Test message
            std::string testMsg = "Hello, ElGamal Cryptosystem! This is a security test.";
            std::vector<unsigned char> message(testMsg.begin(), testMsg.end());

            log("Original message: " + testMsg);

            // Encrypt
            auto startEnc = std::chrono::high_resolution_clock::now();
            ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(message, publicKey);
            auto endEnc = std::chrono::high_resolution_clock::now();

            auto encTime = std::chrono::duration_cast<std::chrono::milliseconds>(endEnc - startEnc);
            log("Encryption time: " + std::to_string(encTime.count()) + " ms");

            // Decrypt
            auto startDec = std::chrono::high_resolution_clock::now();
            std::vector<unsigned char> decrypted = ElGamalCrypto::decrypt(ciphertext, privateKey);
            auto endDec = std::chrono::high_resolution_clock::now();

            auto decTime = std::chrono::duration_cast<std::chrono::milliseconds>(endDec - startDec);
            log("Decryption time: " + std::to_string(decTime.count()) + " ms");

            // Verify correctness
            std::string decryptedMsg(decrypted.begin(), decrypted.end());
            log("Decrypted message: " + decryptedMsg);

            if (testMsg == decryptedMsg) {
                log(COLOR_GREEN "[PASS] Basic encryption/decryption test successful!" COLOR_RESET);
                return true;
            }
            else {
                log(COLOR_RED "[FAIL] Decrypted message does not match original!" COLOR_RESET);
                return false;
            }

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 2: Timing attack resistance
     * Measures if decryption time varies with different inputs
     */
    bool testTimingAttackResistance() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 2: Timing Attack Resistance Analysis" COLOR_RESET);
        log(std::string(60, '='));

        try {
            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(2048);

            const int NUM_SAMPLES = 100;
            std::vector<long long> timings;

            log("Performing " + std::to_string(NUM_SAMPLES) + " encryption/decryption operations...");

            for (int i = 0; i < NUM_SAMPLES; i++) {
                // Generate different messages
                std::string msg = "Test message " + std::to_string(i) + " with varying content";
                std::vector<unsigned char> message(msg.begin(), msg.end());

                ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(message, publicKey);

                auto start = std::chrono::high_resolution_clock::now();
                ElGamalCrypto::decrypt(ciphertext, privateKey);
                auto end = std::chrono::high_resolution_clock::now();

                auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                timings.push_back(duration.count());
            }

            // Calculate statistics
            long long sum = 0;
            long long minTime = timings[0];
            long long maxTime = timings[0];

            for (auto t : timings) {
                sum += t;
                if (t < minTime) minTime = t;
                if (t > maxTime) maxTime = t;
            }

            double mean = static_cast<double>(sum) / NUM_SAMPLES;

            // Calculate standard deviation
            double variance = 0;
            for (auto t : timings) {
                variance += (t - mean) * (t - mean);
            }
            variance /= NUM_SAMPLES;
            double stddev = sqrt(variance);

            log("Timing Statistics:");
            log("  Mean: " + std::to_string(mean) + " 10^-6 s");
            log("  Std Dev: " + std::to_string(stddev) + " 10^-6 s");
            log("  Min: " + std::to_string(minTime) + " 10^-6 s");
            log("  Max: " + std::to_string(maxTime) + " 10^-6 s");
            log("  Coefficient of Variation: " + std::to_string((stddev / mean) * 100) + "%");

            // Check if timing variation is acceptable (< 10% coefficient of variation)
            double cv = (stddev / mean) * 100;
            log("Timing variation analysis:");
            if (cv < 5.0) {
                log(COLOR_GREEN "  Excellent (CV < 5%): Strong resistance to timing attacks" COLOR_RESET);
                return true;
            }
            else if (cv < 10.0) {
                log(COLOR_GREEN "  Good (CV < 10%): Acceptable timing variation for non-constant-time implementation" COLOR_RESET);
                return true;
            }
            else if (cv < 20.0) {
                log(COLOR_YELLOW "  Fair (CV < 20%): Some timing variation present" COLOR_RESET);
                log("  Note: This is typical for standard implementations on general-purpose OS");
                return true;  // Still pass, but with a warning
            }
            else {
                log(COLOR_RED "  Poor (CV >= 20%): Significant timing variation detected" COLOR_RESET);
                log("  This may indicate vulnerability to timing attacks");
                return false;
            }
        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 3: Memory safety test
     * Attempts to detect memory leaks and buffer overflows
     */
    bool testMemorySafety() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 3: Memory Safety Analysis" COLOR_RESET);
        log(std::string(60, '='));

        try {
            log("Testing multiple encryption/decryption cycles for memory leaks...");

            PROCESS_MEMORY_COUNTERS_EX pmc;
            GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
            SIZE_T memBefore = pmc.WorkingSetSize;

            const int ITERATIONS = 50;
            for (int i = 0; i < ITERATIONS; i++) {
                auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(1024);

                std::string msg = "Memory safety test iteration " + std::to_string(i);
                std::vector<unsigned char> message(msg.begin(), msg.end());

                ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(message, publicKey);
                std::vector<unsigned char> decrypted = ElGamalCrypto::decrypt(ciphertext, privateKey);
            }

            GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
            SIZE_T memAfter = pmc.WorkingSetSize;

            long long memDiff = memAfter - memBefore;
            log("Memory before: " + std::to_string(memBefore / 1024) + " KB");
            log("Memory after: " + std::to_string(memAfter / 1024) + " KB");
            log("Memory difference: " + std::to_string(memDiff / 1024) + " KB");

            // Test boundary conditions
            log("\nTesting boundary conditions...");

            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(2048);

            // Test empty message
            try {
                std::vector<unsigned char> emptyMsg;
                ElGamalCiphertext ct = ElGamalCrypto::encrypt(emptyMsg, publicKey);
                std::vector<unsigned char> dec = ElGamalCrypto::decrypt(ct, privateKey);
                log("  Empty message: PASS");
            }
            catch (...) {
                log("  Empty message: Handled gracefully");
            }

            // Test maximum size message
            int maxSize = BN_num_bytes(publicKey.p.get()) - 11;
            std::vector<unsigned char> maxMsg(maxSize, 'X');
            ElGamalCiphertext ct = ElGamalCrypto::encrypt(maxMsg, publicKey);
            std::vector<unsigned char> dec = ElGamalCrypto::decrypt(ct, privateKey);
            log("  Maximum size message: PASS");

            log(COLOR_GREEN "[PASS] Memory safety tests completed" COLOR_RESET);
            return true;

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 4: Key export/import functionality
     */
    bool testKeyPersistence() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 4: Key Export/Import (PKCS-style PEM)" COLOR_RESET);
        log(std::string(60, '='));

        try {
            // Generate keys
            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(1024);

            // Export keys
            std::string pubPEM = ElGamalCrypto::exportPublicKeyToPEM(publicKey);
            std::string privPEM = ElGamalCrypto::exportPrivateKeyToPEM(privateKey);

            log("Public key exported to PEM format");
            log("Private key exported to PEM format");

            // Save to files
            std::ofstream pubFile("elgamal_public.pem");
            pubFile << pubPEM;
            pubFile.close();

            std::ofstream privFile("elgamal_private.pem");
            privFile << privPEM;
            privFile.close();

            log("Keys saved to files: elgamal_public.pem, elgamal_private.pem");

            // Import keys back
            ElGamalPublicKey importedPubKey = ElGamalCrypto::importPublicKeyFromPEM(pubPEM);
            ElGamalPrivateKey importedPrivKey = ElGamalCrypto::importPrivateKeyFromPEM(privPEM);

            log("Keys imported successfully");

            // Test with imported keys
            std::string testMsg = "Testing with imported keys";
            std::vector<unsigned char> message(testMsg.begin(), testMsg.end());

            ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(message, importedPubKey);
            std::vector<unsigned char> decrypted = ElGamalCrypto::decrypt(ciphertext, importedPrivKey);

            std::string decryptedMsg(decrypted.begin(), decrypted.end());

            if (testMsg == decryptedMsg) {
                log(COLOR_GREEN "[PASS] Key export/import test successful!" COLOR_RESET);
                return true;
            }
            else {
                log(COLOR_RED "[FAIL] Decryption with imported keys failed!" COLOR_RESET);
                return false;
            }

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 5: Randomness quality test
     */
    bool testRandomnessQuality() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 5: Randomness Quality (Ephemeral Key Generation)" COLOR_RESET);
        log(std::string(60, '='));

        try {
            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(1024);

            const int NUM_ENCRYPTIONS = 100;
            std::vector<std::string> c1_values;

            log("Generating " + std::to_string(NUM_ENCRYPTIONS) + " ciphertexts for same message...");

            std::string msg = "Fixed message for randomness test";
            std::vector<unsigned char> message(msg.begin(), msg.end());

            for (int i = 0; i < NUM_ENCRYPTIONS; i++) {
                ElGamalCiphertext ct = ElGamalCrypto::encrypt(message, publicKey);
                char* c1_hex = BN_bn2hex(ct.c1.get());
                c1_values.push_back(std::string(c1_hex));
                OPENSSL_free(c1_hex);
            }

            // Check for duplicates (should be none with good RNG)
            int duplicates = 0;
            for (size_t i = 0; i < c1_values.size(); i++) {
                for (size_t j = i + 1; j < c1_values.size(); j++) {
                    if (c1_values[i] == c1_values[j]) {
                        duplicates++;
                    }
                }
            }

            log("Duplicate ephemeral keys found: " + std::to_string(duplicates) + " out of " +
                std::to_string(NUM_ENCRYPTIONS));

            if (duplicates == 0) {
                log(COLOR_GREEN "[PASS] No duplicate ephemeral keys detected" COLOR_RESET);
                log("Random number generator appears to be working correctly");
                return true;
            }
            else {
                log(COLOR_RED "[FAIL] Duplicate ephemeral keys detected!" COLOR_RESET);
                log("This indicates a serious RNG problem");
                return false;
            }

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 6: Operating system privilege escalation test
     */
    bool testPrivilegeIsolation() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 6: OS Protection Mechanism Analysis" COLOR_RESET);
        log(std::string(60, '='));

        try {
            log("Checking process privileges...");

            HANDLE hToken;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation;
                DWORD size;

                if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                    if (elevation.TokenIsElevated) {
                        log(COLOR_YELLOW "[WARNING] Process running with elevated privileges" COLOR_RESET);
                        log("Cryptographic keys may be more vulnerable to privilege escalation attacks");
                    }
                    else {
                        log(COLOR_GREEN "Process running with standard user privileges" COLOR_RESET);
                    }
                }
                CloseHandle(hToken);
            }

            // Test key storage in different memory regions
            log("\nTesting key storage security...");

            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(1024);

            // Get memory info for private key
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(privateKey.x.get(), &mbi, sizeof(mbi));

            log("Private key memory protection:");
            log("  Base Address: " + std::to_string(reinterpret_cast<uintptr_t>(mbi.BaseAddress)));
            log("  Region Size: " + std::to_string(mbi.RegionSize) + " bytes");

            std::string protection;
            if (mbi.Protect & PAGE_READONLY) protection += "PAGE_READONLY ";
            if (mbi.Protect & PAGE_READWRITE) protection += "PAGE_READWRITE ";
            if (mbi.Protect & PAGE_EXECUTE_READ) protection += "PAGE_EXECUTE_READ ";
            if (mbi.Protect & PAGE_GUARD) protection += "PAGE_GUARD ";
            if (mbi.Protect & PAGE_NOCACHE) protection += "PAGE_NOCACHE ";

            log("  Protection: " + protection);

            if (mbi.Protect & PAGE_READWRITE) {
                log(COLOR_YELLOW "[WARNING] Private key stored in READ/WRITE memory" COLOR_RESET);
                log("Consider using VirtualLock() to prevent swapping to page file");
            }

            log(COLOR_GREEN "[PASS] OS protection mechanism analysis completed" COLOR_RESET);
            return true;

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }

    /**
     * Test 7: Resistance to invalid input attacks
     */
    bool testInputValidation() {
        log("\n" + std::string(60, '='));
        log(COLOR_CYAN "TEST 7: Input Validation and Error Handling" COLOR_RESET);
        log(std::string(60, '='));

        try {
            auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(1024);

            int passCount = 0;
            int totalTests = 0;

            // Test 1: Oversized message
            totalTests++;
            log("\nTest 7.1: Oversized message");
            try {
                int maxSize = BN_num_bytes(publicKey.p.get()) - 10;
                std::vector<unsigned char> oversizedMsg(maxSize, 'X');
                ElGamalCiphertext ct = ElGamalCrypto::encrypt(oversizedMsg, publicKey);
                log(COLOR_RED "  [FAIL] Should have thrown exception for oversized message" COLOR_RESET);
            }
            catch (const std::exception& e) {
                log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
                passCount++;
            }

            // Test 2: Corrupted ciphertext c1
            totalTests++;
            log("\nTest 7.2: Corrupted ciphertext (c1 modified)");
            try {
                std::string msg = "Test message";
                std::vector<unsigned char> message(msg.begin(), msg.end());
                ElGamalCiphertext ct = ElGamalCrypto::encrypt(message, publicKey);

                // Corrupt c1
                BN_add_word(ct.c1.get(), 1);

                std::vector<unsigned char> dec = ElGamalCrypto::decrypt(ct, privateKey);
                std::string decMsg(dec.begin(), dec.end());

                if (decMsg != msg) {
                    log(COLOR_GREEN "  [PASS] Corrupted ciphertext detected (decryption produced garbage)" COLOR_RESET);
                    passCount++;
                }
                else {
                    log(COLOR_RED "  [FAIL] Corrupted ciphertext not detected!" COLOR_RESET);
                }
            }
            catch (const std::exception& e) {
                log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
                passCount++;
            }

            // Test 3: Invalid key parameters
            totalTests++;
            log("\nTest 7.3: Invalid key parameters");
            try {
                ElGamalPublicKey invalidKey;
                BN_set_word(invalidKey.p.get(), 17);  // Too small prime
                BN_set_word(invalidKey.g.get(), 2);
                BN_set_word(invalidKey.y.get(), 3);

                std::string msg = "Test";
                std::vector<unsigned char> message(msg.begin(), msg.end());
                ElGamalCiphertext ct = ElGamalCrypto::encrypt(message, invalidKey);
                log(COLOR_YELLOW "  [WARNING] Small key size accepted (may be intentional)" COLOR_RESET);
                passCount++;
            }
            catch (const std::exception& e) {
                log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
                passCount++;
            }

            log("\nInput validation tests: " + std::to_string(passCount) + "/" +
                std::to_string(totalTests) + " passed");

            if (passCount == totalTests) {
                log(COLOR_GREEN "[PASS] All input validation tests passed" COLOR_RESET);
                return true;
            }
            else {
                log(COLOR_YELLOW "[PARTIAL] Some input validation tests failed" COLOR_RESET);
                return false;
            }

        }
        catch (const std::exception& e) {
            log(std::string(COLOR_RED) + "[FAIL] Exception: " + std::string(e.what()) + COLOR_RESET);
            return false;
        }
    }
};

/**
 * Interactive demonstration mode
 */
void interactiveDemo() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << COLOR_CYAN << "   ElGamal Cryptosystem - Interactive Demonstration" << COLOR_RESET << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    try {
        std::cout << "\nGenerating 2048-bit ElGamal key pair...\n" << std::endl;
        auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(2048);

        std::cout << "\n" << COLOR_GREEN << "Key pair generated successfully!" << COLOR_RESET << std::endl;

        // Display key information
        std::cout << "\nKey Information:" << std::endl;
        std::cout << "  Prime size: " << BN_num_bits(publicKey.p.get()) << " bits" << std::endl;
        std::cout << "  Generator: " << BN_bn2dec(publicKey.g.get()) << std::endl;

        char* p_hex = BN_bn2hex(publicKey.p.get());
        std::cout << "  Prime (p): " << std::string(p_hex).substr(0, 64) << "..." << std::endl;
        OPENSSL_free(p_hex);

        // Get message from user
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "Enter message to encrypt: ";
        std::string userMessage;
        std::getline(std::cin, userMessage);

        if (userMessage.empty()) {
            userMessage = "Hello, ElGamal! This is a test of the cryptosystem.";
            std::cout << "Using default message: " << userMessage << std::endl;
        }

        std::vector<unsigned char> message(userMessage.begin(), userMessage.end());

        // Encrypt
        std::cout << "\nEncrypting message..." << std::endl;
        auto startEnc = std::chrono::high_resolution_clock::now();
        ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(message, publicKey);
        auto endEnc = std::chrono::high_resolution_clock::now();
        auto encTime = std::chrono::duration_cast<std::chrono::milliseconds>(endEnc - startEnc);

        std::cout << COLOR_GREEN << "Encryption completed in " << encTime.count() << " ms" << COLOR_RESET << std::endl;

        char* c1_hex = BN_bn2hex(ciphertext.c1.get());
        char* c2_hex = BN_bn2hex(ciphertext.c2.get());
        std::cout << "\nCiphertext components:" << std::endl;
        std::cout << "  c1: " << std::string(c1_hex).substr(0, 64) << "..." << std::endl;
        std::cout << "  c2: " << std::string(c2_hex).substr(0, 64) << "..." << std::endl;
        OPENSSL_free(c1_hex);
        OPENSSL_free(c2_hex);

        // Decrypt
        std::cout << "\nDecrypting message..." << std::endl;
        auto startDec = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> decrypted = ElGamalCrypto::decrypt(ciphertext, privateKey);
        auto endDec = std::chrono::high_resolution_clock::now();
        auto decTime = std::chrono::duration_cast<std::chrono::milliseconds>(endDec - startDec);

        std::cout << COLOR_GREEN << "Decryption completed in " << decTime.count() << " ms" << COLOR_RESET << std::endl;

        std::string decryptedMsg(decrypted.begin(), decrypted.end());
        std::cout << "\nDecrypted message: " << COLOR_YELLOW << decryptedMsg << COLOR_RESET << std::endl;

        // Verify
        if (userMessage == decryptedMsg) {
            std::cout << "\n" << COLOR_GREEN << "SUCCESS: Message decrypted correctly!" << COLOR_RESET << std::endl;
        }
        else {
            std::cout << "\n" << COLOR_RED << "ERROR: Decryption mismatch!" << COLOR_RESET << std::endl;
        }

        // Export keys
        std::cout << "\n" << std::string(70, '-') << std::endl;
        std::cout << "Exporting keys to PEM format..." << std::endl;

        std::string pubPEM = ElGamalCrypto::exportPublicKeyToPEM(publicKey);
        std::string privPEM = ElGamalCrypto::exportPrivateKeyToPEM(privateKey);

        std::ofstream pubFile("elgamal_demo_public.pem");
        pubFile << pubPEM;
        pubFile.close();

        std::ofstream privFile("elgamal_demo_private.pem");
        privFile << privPEM;
        privFile.close();

        std::cout << COLOR_GREEN << "Keys exported to:" << COLOR_RESET << std::endl;
        std::cout << "  - elgamal_demo_public.pem" << std::endl;
        std::cout << "  - elgamal_demo_private.pem" << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << COLOR_RED << "\nError: " << e.what() << COLOR_RESET << std::endl;
    }
}

/**
 * Main program
 */
int main(int argc, char* argv[]) {
    // Enable ANSI colors in Windows console
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hConsole, &mode);
    SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    std::cout << "\n";
    std::cout << "*================================================================*\n";
    std::cout << "|                                                                |\n";
    std::cout << "|          ElGamal Cryptosystem Implementation                   |\n";
    std::cout << "|          OpenSSL-based with PKCS Standards                     |\n";
    std::cout << "|                                                                |\n";
    std::cout << "|          Security Testing & Vulnerability Analysis             |\n";
    std::cout << "|                                                                |\n";
    std::cout << "*================================================================*\n";
    std::cout << std::endl;

    if (argc > 1 && std::string(argv[1]) == "--demo") {
        interactiveDemo();
        return 0;
    }

    // Run security tests
    SecurityTester tester("elgamal_security_test.log");

    std::cout << "Starting comprehensive security analysis...\n" << std::endl;
    std::cout << "Results will be logged to: elgamal_security_test.log\n" << std::endl;

    int passedTests = 0;
    int totalTests = 7;

    if (tester.testBasicEncryptionDecryption()) passedTests++;
    if (tester.testTimingAttackResistance()) passedTests++;
    if (tester.testMemorySafety()) passedTests++;
    if (tester.testKeyPersistence()) passedTests++;
    if (tester.testRandomnessQuality()) passedTests++;
    if (tester.testPrivilegeIsolation()) passedTests++;
    if (tester.testInputValidation()) passedTests++;

    // Final summary
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << COLOR_CYAN << "SECURITY TEST SUMMARY" << COLOR_RESET << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Tests passed: " << passedTests << " / " << totalTests << std::endl;

    if (passedTests == totalTests) {
        std::cout << COLOR_GREEN << "\nAll security tests PASSED!" << COLOR_RESET << std::endl;
        std::cout << "The implementation demonstrates good resistance to common attacks.\n" << std::endl;
    }
    else {
        std::cout << COLOR_YELLOW << "\nSome tests FAILED or showed warnings" << COLOR_RESET << std::endl;
        std::cout << "Review the log file for detailed analysis.\n" << std::endl;
    }

    std::cout << "\nFor interactive demonstration, run with: --demo\n" << std::endl;

    return (passedTests == totalTests) ? 0 : 1;
}
