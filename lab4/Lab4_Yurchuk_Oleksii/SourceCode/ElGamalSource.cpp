#include "Header.h"


// Initialize OpenSSL (call once at program start)
class OpenSSLInitializer {
public:
    OpenSSLInitializer() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }
    ~OpenSSLInitializer() {
        EVP_cleanup();
        ERR_free_strings();
    }
};

static OpenSSLInitializer openssl_init;

std::string ElGamalCrypto::getOpenSSLError() {
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    return std::string(err_buf);
}

BN_ptr ElGamalCrypto::generateSafePrime(int bits, BN_CTX* ctx) {
    BN_ptr p(BN_new());
    BN_ptr q(BN_new());

    if (!p || !q) {
        throw std::runtime_error("Failed to allocate BIGNUM");
    }

    // Generate a safe prime p = 2q + 1 where q is also prime
    // This ensures a large prime-order subgroup
    int ret = BN_generate_prime_ex(q.get(), bits - 1, 1, nullptr, nullptr, nullptr);
    if (ret != 1) {
        throw std::runtime_error("Failed to generate prime q: " + getOpenSSLError());
    }

    // p = 2q + 1
    BN_lshift1(p.get(), q.get());  // p = 2q
    BN_add_word(p.get(), 1);        // p = 2q + 1

    // Verify that p is prime
    int is_prime = BN_check_prime(p.get(), ctx, nullptr);
    if (is_prime != 1) {
        // If not prime, use standard prime generation
        ret = BN_generate_prime_ex(p.get(), bits, 1, nullptr, nullptr, nullptr);
        if (ret != 1) {
            throw std::runtime_error("Failed to generate safe prime p: " + getOpenSSLError());
        }
    }

    return p;
}

BN_ptr ElGamalCrypto::findGenerator(const BIGNUM* p, const BIGNUM* q, BN_CTX* ctx) {
    BN_ptr g(BN_new());
    BN_ptr exp(BN_new());
    BN_ptr result(BN_new());
    BN_ptr one(BN_new());

    if (!g || !exp || !result || !one) {
        throw std::runtime_error("Failed to allocate BIGNUM for generator search");
    }

    BN_one(one.get());

    // Try small values first (2, 3, 4, 5...)
    for (int candidate = 2; candidate < 100; candidate++) {
        BN_set_word(g.get(), candidate);

        // Check if g^q mod p != 1
        // If p = 2q + 1, we want g to generate a large subgroup
        if (q != nullptr) {
            BN_mod_exp(result.get(), g.get(), q, p, ctx);
            if (BN_cmp(result.get(), one.get()) != 0) {
                return g;
            }
        }
        else {
            // Fallback: just use 2 as generator
            return g;
        }
    }

    // If no small generator found, use 2
    BN_set_word(g.get(), 2);
    return g;
}

BN_ptr ElGamalCrypto::generateRandomRange(const BIGNUM* n, BN_CTX* ctx) {
    BN_ptr result(BN_new());
    BN_ptr n_minus_2(BN_new());

    if (!result || !n_minus_2) {
        throw std::runtime_error("Failed to allocate BIGNUM for random generation");
    }

    // Generate random in [1, n-2]
    BN_copy(n_minus_2.get(), n);
    BN_sub_word(n_minus_2.get(), 2);

    int ret = BN_rand_range(result.get(), n_minus_2.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to generate random number: " + getOpenSSLError());
    }

    BN_add_word(result.get(), 1);  // Shift range to [1, n-2]

    return result;
}

std::vector<unsigned char> ElGamalCrypto::applyPKCS1Padding(
    const std::vector<unsigned char>& message,
    size_t blockSize) {

    // PKCS#1 v1.5 padding for encryption: 0x00 || 0x02 || PS || 0x00 || M
    // PS is at least 8 random non-zero bytes

    // Validate block size is sufficient for PKCS#1 padding
    if (blockSize < 11) {
        throw std::runtime_error("Block size too small for PKCS#1 padding (minimum 11 bytes)");
    }

    if (message.size() > blockSize - 11) {
        throw std::runtime_error("Message too long for PKCS#1 padding");
    }

    std::vector<unsigned char> padded(blockSize, 0);
    size_t psLen = blockSize - message.size() - 3;

    if (psLen < 8) {
        throw std::runtime_error("Insufficient padding space (PS must be at least 8 bytes)");
    }

    padded[0] = 0x00;
    padded[1] = 0x02;

    // Generate random non-zero padding bytes
    for (size_t i = 0; i < psLen; i++) {
        unsigned char randByte;
        do {
            if (RAND_bytes(&randByte, 1) != 1) {
                throw std::runtime_error("Failed to generate random padding: " + getOpenSSLError());
            }
        } while (randByte == 0x00);
        padded[2 + i] = randByte;
    }

    padded[2 + psLen] = 0x00;

    // Copy message to the end
    for (size_t i = 0; i < message.size(); i++) {
        padded[3 + psLen + i] = message[i];
    }

    return padded;
}


std::vector<unsigned char> ElGamalCrypto::removePKCS1Padding(
    const std::vector<unsigned char>& paddedData) {

    if (paddedData.size() < 11) {
        throw std::runtime_error("Invalid padded data length");
    }

    if (paddedData[0] != 0x00 || paddedData[1] != 0x02) {
        throw std::runtime_error("Invalid PKCS#1 padding format");
    }

    // Find the 0x00 separator
    size_t i = 2;
    while (i < paddedData.size() && paddedData[i] != 0x00) {
        i++;
    }

    if (i >= paddedData.size() || i < 10) {
        throw std::runtime_error("Invalid PKCS#1 padding structure");
    }

    // Extract message after the separator
    return std::vector<unsigned char>(paddedData.begin() + i + 1, paddedData.end());
}

std::pair<ElGamalPublicKey, ElGamalPrivateKey> ElGamalCrypto::generateKeyPair(int keySize) {
    BN_CTX_ptr ctx(BN_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    std::cout << "Generating " << keySize << "-bit ElGamal key pair..." << std::endl;
    std::cout << "Generating safe prime p..." << std::endl;

    // Generate safe prime p
    BN_ptr p = generateSafePrime(keySize, ctx.get());

    std::cout << "Finding generator g..." << std::endl;

    // Calculate q = (p-1)/2 for safe prime
    BN_ptr q(BN_new());
    BN_copy(q.get(), p.get());
    BN_sub_word(q.get(), 1);
    BN_rshift1(q.get(), q.get());

    // Find generator
    BN_ptr g = findGenerator(p.get(), q.get(), ctx.get());

    std::cout << "Generating private key x..." << std::endl;

    // Generate private key x in [1, p-2]
    BN_ptr x = generateRandomRange(p.get(), ctx.get());

    std::cout << "Computing public key y = g^x mod p..." << std::endl;

    // Compute public key y = g^x mod p
    BN_ptr y(BN_new());
    if (!y) {
        throw std::runtime_error("Failed to allocate BIGNUM for public key");
    }

    int ret = BN_mod_exp(y.get(), g.get(), x.get(), p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute public key: " + getOpenSSLError());
    }

    // Create key structures
    ElGamalPublicKey publicKey;
    ElGamalPrivateKey privateKey;

    BN_copy(publicKey.p.get(), p.get());
    BN_copy(publicKey.g.get(), g.get());
    BN_copy(publicKey.y.get(), y.get());

    BN_copy(privateKey.p.get(), p.get());
    BN_copy(privateKey.g.get(), g.get());
    BN_copy(privateKey.x.get(), x.get());

    std::cout << "Key pair generated successfully!" << std::endl;

    return { std::move(publicKey), std::move(privateKey) };
}

ElGamalCiphertext ElGamalCrypto::encrypt(
    const std::vector<unsigned char>& message,
    const ElGamalPublicKey& publicKey) {

    BN_CTX_ptr ctx(BN_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // Get block size (size of p in bytes)
    int blockSize = BN_num_bytes(publicKey.p.get());

    // Apply PKCS#1 padding
    std::vector<unsigned char> paddedMessage = applyPKCS1Padding(message, blockSize);

    // Convert padded message to BIGNUM
    BN_ptr m(BN_new());
    if (!m) {
        throw std::runtime_error("Failed to allocate BIGNUM for message");
    }

    BN_bin2bn(paddedMessage.data(), paddedMessage.size(), m.get());

    // Verify message < p
    if (BN_cmp(m.get(), publicKey.p.get()) >= 0) {
        throw std::runtime_error("Message value >= modulus p");
    }

    // Generate random ephemeral key k in [1, p-2]
    BN_ptr k = generateRandomRange(publicKey.p.get(), ctx.get());

    // Compute c1 = g^k mod p
    ElGamalCiphertext ciphertext;
    int ret = BN_mod_exp(ciphertext.c1.get(), publicKey.g.get(), k.get(),
        publicKey.p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute c1: " + getOpenSSLError());
    }

    // Compute c2 = m * y^k mod p
    BN_ptr yk(BN_new());
    if (!yk) {
        throw std::runtime_error("Failed to allocate BIGNUM for y^k");
    }

    ret = BN_mod_exp(yk.get(), publicKey.y.get(), k.get(), publicKey.p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute y^k: " + getOpenSSLError());
    }

    ret = BN_mod_mul(ciphertext.c2.get(), m.get(), yk.get(), publicKey.p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute c2: " + getOpenSSLError());
    }

    return ciphertext;
}

std::vector<unsigned char> ElGamalCrypto::decrypt(
    const ElGamalCiphertext& ciphertext,
    const ElGamalPrivateKey& privateKey) {

    BN_CTX_ptr ctx(BN_CTX_new());
    if (!ctx) {
        throw std::runtime_error("Failed to create BN_CTX");
    }

    // Compute c1^x mod p
    BN_ptr c1x(BN_new());
    if (!c1x) {
        throw std::runtime_error("Failed to allocate BIGNUM for c1^x");
    }

    int ret = BN_mod_exp(c1x.get(), ciphertext.c1.get(), privateKey.x.get(),
        privateKey.p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute c1^x: " + getOpenSSLError());
    }

    // Compute inverse of c1^x mod p
    BN_ptr c1x_inv(BN_new());
    if (!c1x_inv) {
        throw std::runtime_error("Failed to allocate BIGNUM for inverse");
    }

    BIGNUM* inv_result = BN_mod_inverse(c1x_inv.get(), c1x.get(), privateKey.p.get(), ctx.get());
    if (!inv_result) {
        throw std::runtime_error("Failed to compute modular inverse: " + getOpenSSLError());
    }

    // Compute m = c2 * (c1^x)^-1 mod p
    BN_ptr m(BN_new());
    if (!m) {
        throw std::runtime_error("Failed to allocate BIGNUM for plaintext");
    }

    ret = BN_mod_mul(m.get(), ciphertext.c2.get(), c1x_inv.get(),
        privateKey.p.get(), ctx.get());
    if (ret != 1) {
        throw std::runtime_error("Failed to compute plaintext: " + getOpenSSLError());
    }

    // Convert BIGNUM to bytes - preserve full block size including leading zeros
    size_t blockSize = BN_num_bytes(privateKey.p.get());
    std::vector<unsigned char> paddedData(blockSize, 0);  // Initialize with zeros

    size_t numBytes = BN_num_bytes(m.get());
    // Write to the end of the buffer to preserve leading zeros
    BN_bn2bin(m.get(), paddedData.data() + (blockSize - numBytes));

    // Remove PKCS#1 padding
    return removePKCS1Padding(paddedData);
}

std::string ElGamalCrypto::exportPublicKeyToPEM(const ElGamalPublicKey& publicKey) {
    std::ostringstream oss;

    // Convert BIGNUMs to hex strings
    char* p_hex = BN_bn2hex(publicKey.p.get());
    char* g_hex = BN_bn2hex(publicKey.g.get());
    char* y_hex = BN_bn2hex(publicKey.y.get());

    if (!p_hex || !g_hex || !y_hex) {
        OPENSSL_free(p_hex);
        OPENSSL_free(g_hex);
        OPENSSL_free(y_hex);
        throw std::runtime_error("Failed to convert key to hex");
    }

    oss << "-----BEGIN ELGAMAL PUBLIC KEY-----\n";
    oss << "Prime: " << p_hex << "\n";
    oss << "Generator: " << g_hex << "\n";
    oss << "PublicKey: " << y_hex << "\n";
    oss << "-----END ELGAMAL PUBLIC KEY-----\n";

    OPENSSL_free(p_hex);
    OPENSSL_free(g_hex);
    OPENSSL_free(y_hex);

    return oss.str();
}

std::string ElGamalCrypto::exportPrivateKeyToPEM(const ElGamalPrivateKey& privateKey) {
    std::ostringstream oss;

    char* p_hex = BN_bn2hex(privateKey.p.get());
    char* g_hex = BN_bn2hex(privateKey.g.get());
    char* x_hex = BN_bn2hex(privateKey.x.get());

    if (!p_hex || !g_hex || !x_hex) {
        OPENSSL_free(p_hex);
        OPENSSL_free(g_hex);
        OPENSSL_free(x_hex);
        throw std::runtime_error("Failed to convert key to hex");
    }

    oss << "-----BEGIN ELGAMAL PRIVATE KEY-----\n";
    oss << "Prime: " << p_hex << "\n";
    oss << "Generator: " << g_hex << "\n";
    oss << "PrivateKey: " << x_hex << "\n";
    oss << "-----END ELGAMAL PRIVATE KEY-----\n";

    OPENSSL_free(p_hex);
    OPENSSL_free(g_hex);
    OPENSSL_free(x_hex);

    return oss.str();
}

ElGamalPublicKey ElGamalCrypto::importPublicKeyFromPEM(const std::string& pemString) {
    ElGamalPublicKey publicKey;

    std::istringstream iss(pemString);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("Prime: ") == 0) {
            std::string hex = line.substr(7);
            BIGNUM* temp = publicKey.p.get();
            BN_hex2bn(&temp, hex.c_str());
        }
        else if (line.find("Generator: ") == 0) {
            std::string hex = line.substr(11);
            BIGNUM* temp = publicKey.g.get();
            BN_hex2bn(&temp, hex.c_str());
        }
        else if (line.find("PublicKey: ") == 0) {
            std::string hex = line.substr(11);
            BIGNUM* temp = publicKey.y.get();
            BN_hex2bn(&temp, hex.c_str());
        }
    }

    if (!publicKey.p || !publicKey.g || !publicKey.y) {
        throw std::runtime_error("Failed to parse public key from PEM");
    }

    return publicKey;
}

ElGamalPrivateKey ElGamalCrypto::importPrivateKeyFromPEM(const std::string& pemString) {
    ElGamalPrivateKey privateKey;

    std::istringstream iss(pemString);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("Prime: ") == 0) {
            std::string hex = line.substr(7);
            BIGNUM* temp = privateKey.p.get();
            BN_hex2bn(&temp, hex.c_str());
        }
        else if (line.find("Generator: ") == 0) {
            std::string hex = line.substr(11);
            BIGNUM* temp = privateKey.g.get();
            BN_hex2bn(&temp, hex.c_str());
        }
        else if (line.find("PrivateKey: ") == 0) {
            std::string hex = line.substr(12);
            BIGNUM* temp = privateKey.x.get();
            BN_hex2bn(&temp, hex.c_str());
        }
    }

    if (!privateKey.p || !privateKey.g || !privateKey.x) {
        throw std::runtime_error("Failed to parse private key from PEM");
    }

    return privateKey;
}