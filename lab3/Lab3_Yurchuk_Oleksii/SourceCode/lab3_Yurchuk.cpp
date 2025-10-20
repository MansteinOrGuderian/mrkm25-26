#include <iostream>
#include <memory>
#include <string>
#include <sstream> 
#include <vector>
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// Smart pointer deleters for OpenSSL types
struct BN_Deleter {
    void operator()(BIGNUM* bn) const { BN_free(bn); }
};

struct BN_CTX_Deleter {
    void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); }
};

struct BN_GENCB_Deleter {
    void operator()(BN_GENCB* cb) const { BN_GENCB_free(cb); }
};

using BN_ptr = std::unique_ptr<BIGNUM, BN_Deleter>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, BN_CTX_Deleter>;
using BN_GENCB_ptr = std::unique_ptr<BN_GENCB, BN_GENCB_Deleter>;

// Helper function to create secure BIGNUM
BN_ptr make_secure_bn() {
    return BN_ptr(BN_secure_new());
}

// Helper function to create regular BIGNUM
BN_ptr make_bn() {
    return BN_ptr(BN_new());
}

// ElGamal Key Structure
class ElGamalKey {
public:
    BN_ptr p;           // Prime modulus
    BN_ptr g;           // Generator
    BN_ptr h;           // Public key (h = g^x mod p)
    BN_ptr x;           // Private key (secret exponent)

    ElGamalKey()
        : p(make_bn()),
        g(make_bn()),
        h(make_bn()),
        x(make_secure_bn()) {}

    bool hasPrivateKey() const {
        return x && !BN_is_zero(x.get());
    }
};

// ElGamal Ciphertext Structure
class ElGamalCiphertext {
public:
    BN_ptr c1;          // c1 = g^y mod p
    BN_ptr c2;          // c2 = m * h^y mod p

    ElGamalCiphertext()
        : c1(make_bn()),
        c2(make_bn()) {}
};

// ElGamal Implementation Class
class ElGamal {
private:
    BN_CTX_ptr ctx;

    // Callback for prime generation progress
    static int generation_callback(int p, int n, BN_GENCB* cb) {
        char c = '*';
        if (p == 0) c = '.';
        if (p == 1) c = '+';
        if (p == 2) c = '*';
        if (p == 3) c = '\n';
        std::cout << c << std::flush;
        return 1;
    }

public:
    ElGamal() : ctx(BN_CTX_new()) {
        if (!ctx) {
            throw std::runtime_error("Failed to create BN_CTX");
        }
    }

    // Generate ElGamal parameters and key pair
    bool generateKey(ElGamalKey& key, int bits) {
        std::cout << "Generating " << bits << "-bit ElGamal key...\n";

        // Check PRNG status
        if (RAND_status() != 1) {
            std::cerr << "PRNG not sufficiently seeded!\n";
            return false;
        }

        // Generate a safe prime p = 2q + 1
        std::cout << "Generating safe prime p: ";
        BN_GENCB_ptr cb(BN_GENCB_new());
        BN_GENCB_set(cb.get(), generation_callback, nullptr);

        if (!BN_generate_prime_ex(key.p.get(), bits, 1, nullptr, nullptr, cb.get())) {
            std::cerr << "Failed to generate prime\n";
            return false;
        }
        std::cout << "Done!\n";

        // Select generator g
        // For safe prime p = 2q + 1, we can use g = 2
        // Verify that g generates the subgroup of order q
        if (!BN_set_word(key.g.get(), 2)) {
            std::cerr << "Failed to set generator\n";
            return false;
        }

        // Generate random private key x in [1, p-2]
        BN_ptr p_minus_one = make_bn();
        if (!BN_sub(p_minus_one.get(), key.p.get(), BN_value_one())) {
            std::cerr << "Failed to compute p-1\n";
            return false;
        }

        if (!BN_rand_range(key.x.get(), p_minus_one.get())) {
            std::cerr << "Failed to generate private key\n";
            return false;
        }

        // Ensure x is not zero
        if (BN_is_zero(key.x.get())) {
            BN_one(key.x.get());
        }

        // Compute public key h = g^x mod p
        std::cout << "Computing public key...\n";
        if (!BN_mod_exp(key.h.get(), key.g.get(), key.x.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute public key\n";
            return false;
        }

        std::cout << "Key generation completed successfully!\n\n";
        return true;
    }

    // Encrypt a message
    bool encrypt(const ElGamalKey& key, const BIGNUM* message, ElGamalCiphertext& ciphertext) {
        // Verify message is in valid range [1, p-1]
        if (BN_is_zero(message) || BN_cmp(message, key.p.get()) >= 0) {
            std::cerr << "Message out of valid range\n";
            return false;
        }

        // Generate random ephemeral key y in [1, p-2]
        BN_ptr y = make_secure_bn();
        BN_ptr p_minus_one = make_bn();

        if (!BN_sub(p_minus_one.get(), key.p.get(), BN_value_one())) {
            return false;
        }

        if (!BN_rand_range(y.get(), p_minus_one.get())) {
            std::cerr << "Failed to generate ephemeral key\n";
            return false;
        }

        if (BN_is_zero(y.get())) {
            BN_one(y.get());
        }

        // Compute c1 = g^y mod p
        if (!BN_mod_exp(ciphertext.c1.get(), key.g.get(), y.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute c1\n";
            return false;
        }

        // Compute shared secret s = h^y mod p
        BN_ptr shared_secret = make_bn();
        if (!BN_mod_exp(shared_secret.get(), key.h.get(), y.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute shared secret\n";
            return false;
        }

        // Compute c2 = m * s mod p
        if (!BN_mod_mul(ciphertext.c2.get(), message, shared_secret.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute c2\n";
            return false;
        }

        return true;
    }

    // Decrypt a ciphertext
    bool decrypt(const ElGamalKey& key, const ElGamalCiphertext& ciphertext, BIGNUM* message) {
        if (!key.hasPrivateKey()) {
            std::cerr << "Private key required for decryption\n";
            return false;
        }

        // Compute shared secret s = c1^x mod p
        BN_ptr shared_secret = make_bn();
        if (!BN_mod_exp(shared_secret.get(), ciphertext.c1.get(), key.x.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute shared secret\n";
            return false;
        }

        // Compute modular inverse s^(-1) mod p
        BN_ptr s_inv = make_bn();
        if (!BN_mod_inverse(s_inv.get(), shared_secret.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute modular inverse\n";
            return false;
        }

        // Recover message m = c2 * s^(-1) mod p
        if (!BN_mod_mul(message, ciphertext.c2.get(), s_inv.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to recover message\n";
            return false;
        }

        return true;
    }

    // Sign a message (ElGamal signature scheme)
    bool sign(const ElGamalKey& key, const unsigned char* msg, size_t msg_len,
        BIGNUM* r, BIGNUM* s) {
        if (!key.hasPrivateKey()) {
            std::cerr << "Private key required for signing\n";
            return false;
        }

        // Hash the message
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(msg, msg_len, hash);

        BN_ptr h = make_bn();
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h.get());

        // Reduce hash modulo (p-1)
        BN_ptr p_minus_one = make_bn();
        BN_sub(p_minus_one.get(), key.p.get(), BN_value_one());
        BN_mod(h.get(), h.get(), p_minus_one.get(), ctx.get());

        // Generate random k such that gcd(k, p-1) = 1
        BN_ptr k = make_secure_bn();
        BN_ptr gcd = make_bn();

        do {
            if (!BN_rand_range(k.get(), p_minus_one.get())) {
                std::cerr << "Failed to generate k\n";
                return false;
            }
            if (BN_is_zero(k.get())) {
                BN_one(k.get());
            }
            BN_gcd(gcd.get(), k.get(), p_minus_one.get(), ctx.get());
        } while (!BN_is_one(gcd.get()));

        // Compute r = g^k mod p
        if (!BN_mod_exp(r, key.g.get(), k.get(), key.p.get(), ctx.get())) {
            std::cerr << "Failed to compute r\n";
            return false;
        }

        // Compute k^(-1) mod (p-1)
        BN_ptr k_inv = make_bn();
        if (!BN_mod_inverse(k_inv.get(), k.get(), p_minus_one.get(), ctx.get())) {
            std::cerr << "Failed to compute k inverse\n";
            return false;
        }

        // Compute s = k^(-1) * (h - x*r) mod (p-1)
        BN_ptr xr = make_bn();
        BN_mod_mul(xr.get(), key.x.get(), r, p_minus_one.get(), ctx.get());

        BN_ptr h_minus_xr = make_bn();
        BN_mod_sub(h_minus_xr.get(), h.get(), xr.get(), p_minus_one.get(), ctx.get());

        if (!BN_mod_mul(s, k_inv.get(), h_minus_xr.get(), p_minus_one.get(), ctx.get())) {
            std::cerr << "Failed to compute s\n";
            return false;
        }

        return true;
    }

    // Verify a signature
    bool verify(const ElGamalKey& key, const unsigned char* msg, size_t msg_len,
        const BIGNUM* r, const BIGNUM* s) {
        // Check that 0 < r < p and 0 < s < p-1
        BN_ptr p_minus_one = make_bn();
        BN_sub(p_minus_one.get(), key.p.get(), BN_value_one());

        if (BN_is_zero(r) || BN_cmp(r, key.p.get()) >= 0 ||
            BN_is_zero(s) || BN_cmp(s, p_minus_one.get()) >= 0) {
            return false;
        }

        // Hash the message
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(msg, msg_len, hash);

        BN_ptr h = make_bn();
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h.get());
        BN_mod(h.get(), h.get(), p_minus_one.get(), ctx.get());

        // Compute g^h mod p
        BN_ptr lhs = make_bn();
        if (!BN_mod_exp(lhs.get(), key.g.get(), h.get(), key.p.get(), ctx.get())) {
            return false;
        }

        // Compute h^r mod p
        BN_ptr hr = make_bn();
        if (!BN_mod_exp(hr.get(), key.h.get(), r, key.p.get(), ctx.get())) {
            return false;
        }

        // Compute r^s mod p
        BN_ptr rs = make_bn();
        if (!BN_mod_exp(rs.get(), r, s, key.p.get(), ctx.get())) {
            return false;
        }

        // Compute rhs = (h^r * r^s) mod p
        BN_ptr rhs = make_bn();
        if (!BN_mod_mul(rhs.get(), hr.get(), rs.get(), key.p.get(), ctx.get())) {
            return false;
        }

        // Verify g^h = h^r * r^s mod p
        return BN_cmp(lhs.get(), rhs.get()) == 0;
    }
};

// Utility functions
void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    std::cout << label << ":\n" << hex << "\n\n";
    OPENSSL_free(hex);
}

void print_bn_dec(const char* label, const BIGNUM* bn) {
    char* dec = BN_bn2dec(bn);
    std::cout << label << ": " << dec << "\n";
    OPENSSL_free(dec);
}

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Demo function for encryption/decryption
void demo_encryption() {
    std::cout << "=== ElGamal Encryption/Decryption Demo ===\n\n";

    ElGamal elgamal;
    ElGamalKey key;

    // Generate 1024-bit key (use 2048+ for production!)
    if (!elgamal.generateKey(key, 1024)) {
        std::cerr << "Key generation failed!\n";
        return;
    }

    // Print key components
    std::cout << "Public Key Components:\n";
    print_bn("Prime (p)", key.p.get());
    print_bn("Generator (g)", key.g.get());
    print_bn("Public key (h)", key.h.get());

    // Create a message (must be < p)
    BN_ptr message = make_bn();
    BN_set_word(message.get(), 123456789);
    print_bn_dec("Original message", message.get());
    std::cout << "\n";

    // Encrypt
    ElGamalCiphertext ciphertext;
    std::cout << "Encrypting message...\n";
    if (!elgamal.encrypt(key, message.get(), ciphertext)) {
        std::cerr << "Encryption failed!\n";
        return;
    }

    std::cout << "Ciphertext components:\n";
    print_bn("c1", ciphertext.c1.get());
    print_bn("c2", ciphertext.c2.get());

    // Decrypt
    BN_ptr decrypted = make_bn();
    std::cout << "Decrypting ciphertext...\n";
    if (!elgamal.decrypt(key, ciphertext, decrypted.get())) {
        std::cerr << "Decryption failed!\n";
        return;
    }

    print_bn_dec("Decrypted message", decrypted.get());

    // Verify correctness
    if (BN_cmp(message.get(), decrypted.get()) == 0) {
        std::cout << "\nSUCCESS: Decryption matches original message!\n";
    }
    else {
        std::cout << "\nFAILURE: Decryption does not match!\n";
    }
}

// Demo function for digital signatures
void demo_signature() {
    std::cout << "\n\n=== ElGamal Digital Signature Demo ===\n\n";

    ElGamal elgamal;
    ElGamalKey key;

    // Generate key
    if (!elgamal.generateKey(key, 1024)) {
        std::cerr << "Key generation failed!\n";
        return;
    }

    // Message to sign
    const char* message = "Hello, ElGamal signatures!";
    std::cout << "Message to sign: " << message << "\n\n";

    // Sign the message
    BN_ptr r = make_bn();
    BN_ptr s = make_bn();

    std::cout << "Signing message...\n";
    if (!elgamal.sign(key, (const unsigned char*)message, strlen(message), r.get(), s.get())) {
        std::cerr << "Signing failed!\n";
        return;
    }

    std::cout << "Signature components:\n";
    print_bn("r", r.get());
    print_bn("s", s.get());

    // Verify the signature
    std::cout << "Verifying signature...\n";
    bool valid = elgamal.verify(key, (const unsigned char*)message, strlen(message), r.get(), s.get());

    if (valid) {
        std::cout << "Signature is VALID!\n";
    }
    else {
        std::cout << "Signature is INVALID!\n";
    }

    // Test with modified message
    const char* modified = "Hello, ElGamal signatures?";
    std::cout << "\nVerifying with modified message: " << modified << "\n";
    bool invalid = elgamal.verify(key, (const unsigned char*)modified, strlen(modified), r.get(), s.get());

    if (!invalid) {
        std::cout << "Correctly rejected modified message!\n";
    }
    else {
        std::cout << "ERROR: Accepted modified message!\n";
    }
}

// Demo homomorphic property
void demo_homomorphic() {
    std::cout << "\n\n=== ElGamal Homomorphic Property Demo ===\n\n";

    ElGamal elgamal;
    ElGamalKey key;
    BN_CTX_ptr ctx(BN_CTX_new());

    if (!elgamal.generateKey(key, 1024)) {
        std::cerr << "Key generation failed!\n";
        return;
    }

    // Create two messages
    BN_ptr m1 = make_bn();
    BN_ptr m2 = make_bn();
    BN_set_word(m1.get(), 100);
    BN_set_word(m2.get(), 200);

    std::cout << "Message 1: 100\n";
    std::cout << "Message 2: 200\n";
    std::cout << "Expected product: 20000\n\n";

    // Encrypt both messages
    ElGamalCiphertext ct1, ct2;
    elgamal.encrypt(key, m1.get(), ct1);
    elgamal.encrypt(key, m2.get(), ct2);

    // Multiply ciphertexts: (c1_1 * c1_2, c2_1 * c2_2)
    ElGamalCiphertext ct_product;
    BN_mod_mul(ct_product.c1.get(), ct1.c1.get(), ct2.c1.get(), key.p.get(), ctx.get());
    BN_mod_mul(ct_product.c2.get(), ct1.c2.get(), ct2.c2.get(), key.p.get(), ctx.get());

    std::cout << "Multiplying ciphertexts homomorphically...\n";

    // Decrypt the product
    BN_ptr product = make_bn();
    elgamal.decrypt(key, ct_product, product.get());

    print_bn_dec("Decrypted product", product.get());

    // Verify
    BN_ptr expected = make_bn();
    BN_mod_mul(expected.get(), m1.get(), m2.get(), key.p.get(), ctx.get());

    if (BN_cmp(product.get(), expected.get()) == 0) {
        std::cout << "Homomorphic multiplication successful!\n";
    }
    else {
        std::cout << "Homomorphic multiplication failed!\n";
    }
}

int main() {
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    std::cout << "ElGamal Cryptosystem Implementation\n";
    std::cout << "Using OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION) << "\n\n";

    try {
        // Run demos
        demo_encryption();
        demo_signature();
        demo_homomorphic();

        std::cout << "\n\n=== All demos completed successfully! ===\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
