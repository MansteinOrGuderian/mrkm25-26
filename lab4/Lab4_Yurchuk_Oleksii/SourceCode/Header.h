#pragma once
#ifndef ELGAMAL_H
#define ELGAMAL_H

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <vector>
#include <memory>
#include <chrono>
#include <windows.h>
#include <Psapi.h>

// Smart pointer deleters for OpenSSL objects
struct BN_Deleter {
    void operator()(BIGNUM* bn) const { if (bn) BN_free(bn); }
};

struct BN_CTX_Deleter {
    void operator()(BN_CTX* ctx) const { if (ctx) BN_CTX_free(ctx); }
};

using BN_ptr = std::unique_ptr<BIGNUM, BN_Deleter>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, BN_CTX_Deleter>;

/**
 * ElGamal Public Key structure
 * Contains domain parameters (p, g) and public key (y)
 */
struct ElGamalPublicKey {
    BN_ptr p;  // Large prime modulus
    BN_ptr g;  // Generator
    BN_ptr y;  // Public key y = g^x mod p

    ElGamalPublicKey()
        : p(BN_new()), g(BN_new()), y(BN_new()) {
        if (!p || !g || !y) {
            throw std::runtime_error("Failed to allocate BIGNUM for public key");
        }
    }
};

/**
 * ElGamal Private Key structure
 * Contains domain parameters and private key (x)
 */
struct ElGamalPrivateKey {
    BN_ptr p;  // Large prime modulus
    BN_ptr g;  // Generator
    BN_ptr x;  // Private key (secret exponent)

    ElGamalPrivateKey()
        : p(BN_new()), g(BN_new()), x(BN_new()) {
        if (!p || !g || !x) {
            throw std::runtime_error("Failed to allocate BIGNUM for private key");
        }
    }
};

/**
 * ElGamal Ciphertext structure
 * Contains two components (c1, c2)
 */
struct ElGamalCiphertext {
    BN_ptr c1;  // c1 = g^k mod p
    BN_ptr c2;  // c2 = m * y^k mod p

    ElGamalCiphertext()
        : c1(BN_new()), c2(BN_new()) {
        if (!c1 || !c2) {
            throw std::runtime_error("Failed to allocate BIGNUM for ciphertext");
        }
    }
};

/**
 * Main ElGamal Cryptosystem class
 * Implements key generation, encryption, and decryption
 */
class ElGamalCrypto {
private:
    static constexpr int DEFAULT_KEY_SIZE = 2048;
    static constexpr int MILLER_RABIN_ROUNDS = 64;

    // Helper function to generate a safe prime
    static BN_ptr generateSafePrime(int bits, BN_CTX* ctx);

    // Helper function to find a suitable generator
    static BN_ptr findGenerator(const BIGNUM* p, const BIGNUM* q, BN_CTX* ctx);

    // Helper function to generate random number in range [1, n-1]
    static BN_ptr generateRandomRange(const BIGNUM* n, BN_CTX* ctx);

    // PKCS#1 v1.5 padding for encryption
    static std::vector<unsigned char> applyPKCS1Padding(
        const std::vector<unsigned char>& message,
        size_t blockSize);

    // Remove PKCS#1 v1.5 padding
    static std::vector<unsigned char> removePKCS1Padding(
        const std::vector<unsigned char>& paddedData);

public:
    /**
     * Generate ElGamal key pair
     * @param keySize Size of the prime in bits (default 2048)
     * @return Pair of (public_key, private_key)
     */
    static std::pair<ElGamalPublicKey, ElGamalPrivateKey> generateKeyPair(
        int keySize = DEFAULT_KEY_SIZE);

    /**
     * Encrypt a message using ElGamal public key
     * @param message Plaintext message
     * @param publicKey ElGamal public key
     * @return Ciphertext structure
     */
    static ElGamalCiphertext encrypt(
        const std::vector<unsigned char>& message,
        const ElGamalPublicKey& publicKey);

    /**
     * Decrypt a ciphertext using ElGamal private key
     * @param ciphertext Encrypted message
     * @param privateKey ElGamal private key
     * @return Decrypted plaintext
     */
    static std::vector<unsigned char> decrypt(
        const ElGamalCiphertext& ciphertext,
        const ElGamalPrivateKey& privateKey);

    /**
     * Export public key to PEM format (custom format following PKCS conventions)
     * @param publicKey Public key to export
     * @return PEM-encoded string
     */
    static std::string exportPublicKeyToPEM(const ElGamalPublicKey& publicKey);

    /**
     * Export private key to PEM format (custom format following PKCS conventions)
     * @param privateKey Private key to export
     * @return PEM-encoded string
     */
    static std::string exportPrivateKeyToPEM(const ElGamalPrivateKey& privateKey);

    /**
     * Import public key from PEM format
     * @param pemString PEM-encoded public key
     * @return ElGamal public key
     */
    static ElGamalPublicKey importPublicKeyFromPEM(const std::string& pemString);

    /**
     * Import private key from PEM format
     * @param pemString PEM-encoded private key
     * @return ElGamal private key
     */
    static ElGamalPrivateKey importPrivateKeyFromPEM(const std::string& pemString);

    /**
     * Get OpenSSL error string
     */
    static std::string getOpenSSLError();
};

#endif // ELGAMAL_H