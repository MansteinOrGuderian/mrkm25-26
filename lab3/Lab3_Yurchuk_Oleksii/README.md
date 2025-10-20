# ElGamal Cryptosystem Implementation in C++ with OpenSSL

A simple demo implementation of the ElGamal cryptosystem using OpenSSL on Windows.

## Features

✅ **Key Generation**: Generate ElGamal key pairs with safe primes
✅ **Encryption/Decryption**: Secure message encryption and decryption
✅ **Digital Signatures**: ElGamal signature generation and verification
✅ **Homomorphic Properties**: Demonstration of multiplicative homomorphism
✅ **Memory Safe**: Uses smart pointers for automatic cleanup
✅ **Error Handling**: Comprehensive error checking and reporting

## Requirements

- **Windows 10/11** (64-bit)
- **Visual Studio 2019+** or **MinGW-w64**
- **OpenSSL 3.x**
- **CMake 3.10+** (optional, for CMake build)

## Installing OpenSSL on Windows

### Option 1: Using Pre-compiled Binaries (Recommended)

1. Download OpenSSL from [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)
2. Install to `C:\OpenSSL` (or note the installation path)
3. Add `C:\OpenSSL\bin` to your PATH environment variable

### Option 2: Using vcpkg

```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg install openssl:x64-windows
.\vcpkg integrate install
```

## Compilation Instructions

### Method 1: Using CMake (Recommended)

```bash
# Create build directory
mkdir build
cd build

# Configure
cmake ..

# Build
cmake --build . --config Release

# Run
.\bin\Release\elgamal_demo.exe
```

### Method 2: Using Visual Studio (MSVC)

```bash
cl /EHsc /std:c++17 /I"C:\OpenSSL\include" elgamal_implementation.cpp ^
   /link /LIBPATH:"C:\OpenSSL\lib" libcrypto.lib ws2_32.lib crypt32.lib advapi32.lib ^
   /OUT:elgamal_demo.exe

# Run
elgamal_demo.exe
```

### Method 3: Using MinGW-w64

```bash
g++ -std=c++17 -O2 -o elgamal_demo.exe elgamal_implementation.cpp ^
    -I"C:/OpenSSL/include" -L"C:/OpenSSL/lib" ^
    -lcrypto -lws2_32 -lcrypt32

# Run
elgamal_demo.exe
```

### Method 4: Using vcpkg with CMake

```bash
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release
.\bin\Release\elgamal_demo.exe
```

## Code Structure

### Main Components

1. **ElGamalKey**: Stores public and private key components (p, g, h, x)
2. **ElGamalCiphertext**: Stores ciphertext pair (c1, c2)
3. **ElGamal Class**: Main implementation with methods:
   - `generateKey()` - Generate key pair
   - `encrypt()` - Encrypt message
   - `decrypt()` - Decrypt ciphertext
   - `sign()` - Generate digital signature
   - `verify()` - Verify digital signature

## Usage Examples

### Basic Encryption/Decryption

```cpp
ElGamal elgamal;
ElGamalKey key;

// Generate 2048-bit key
elgamal.generateKey(key, 2048);

// Create message
BN_ptr message = make_bn();
BN_set_word(message.get(), 42);

// Encrypt
ElGamalCiphertext ciphertext;
elgamal.encrypt(key, message.get(), ciphertext);

// Decrypt
BN_ptr decrypted = make_bn();
elgamal.decrypt(key, ciphertext, decrypted.get());
```

### Digital Signatures

```cpp
ElGamal elgamal;
ElGamalKey key;
elgamal.generateKey(key, 2048);

// Sign message
const char* msg = "Hello, World!";
BN_ptr r = make_bn();
BN_ptr s = make_bn();
elgamal.sign(key, (const unsigned char*)msg, strlen(msg), r.get(), s.get());

// Verify signature
bool valid = elgamal.verify(key, (const unsigned char*)msg, strlen(msg),
                            r.get(), s.get());
```

### Homomorphic Multiplication

```cpp
// Encrypt two messages
BN_ptr m1 = make_bn();
BN_ptr m2 = make_bn();
BN_set_word(m1.get(), 10);
BN_set_word(m2.get(), 20);

ElGamalCiphertext ct1, ct2;
elgamal.encrypt(key, m1.get(), ct1);
elgamal.encrypt(key, m2.get(), ct2);

// Multiply ciphertexts
ElGamalCiphertext ct_product;
BN_CTX_ptr ctx(BN_CTX_new());
BN_mod_mul(ct_product.c1.get(), ct1.c1.get(), ct2.c1.get(), key.p.get(), ctx.get());
BN_mod_mul(ct_product.c2.get(), ct1.c2.get(), ct2.c2.get(), key.p.get(), ctx.get());

// Decrypt product (will be 200)
BN_ptr product = make_bn();
elgamal.decrypt(key, ct_product, product.get());
```

## Demo Output

When you run the program, you'll see three demonstrations:

### 1. Encryption/Decryption Demo

```
=== ElGamal Encryption/Decryption Demo ===

Generating 1024-bit ElGamal key...
Generating safe prime p: .+*+*+*...
Done!
Computing public key...
Key generation completed successfully!

Original message: 123456789

Encrypting message...
Decrypting ciphertext...
Decrypted message: 123456789

SUCCESS: Decryption matches original message!
```

### 2. Digital Signature Demo

```
=== ElGamal Digital Signature Demo ===

Message to sign: Hello, ElGamal signatures!

Signing message...
Verifying signature...
Signature is VALID!

Verifying with modified message...
Correctly rejected modified message!
```

### 3. Homomorphic Property Demo

```
=== ElGamal Homomorphic Property Demo ===

Message 1: 100
Message 2: 200
Expected product: 20000

Multiplying ciphertexts homomorphically...
Decrypted product: 20000

Homomorphic multiplication successful!
```

## Security Considerations

### Key Sizes

- **1024 bits**: Demo/testing only (NOT secure for production)
- **2048 bits**: Minimum for production use (112-bit security)
- **3072 bits**: Recommended for long-term security (128-bit security)
- **4096 bits**: Maximum security (192-bit security)

### Important Security Notes

⚠️ **Never reuse ephemeral keys**: Each encryption/signature must use a fresh random value
⚠️ **Use safe primes**: Implementation generates safe primes (p = 2q + 1)
⚠️ **Secure random generation**: Always check `RAND_status()` before key generation
⚠️ **Message encoding**: Messages must be in range [1, p-1]
⚠️ **Constant-time operations**: For production, enable constant-time flag

### Enabling Constant-Time Operations

```cpp
// Set constant-time flag on private key
BN_set_flags(key.x.get(), BN_FLG_CONSTTIME);
```

## Performance Notes

### Key Generation Time (approximate)

| Bits | Time           |
| ---- | -------------- |
| 1024 | 1-3 seconds    |
| 2048 | 10-30 seconds  |
| 3072 | 30-120 seconds |
| 4096 | 2-10 minutes   |

### Operation Complexity

- **Encryption**: 2 modular exponentiations
- **Decryption**: 1 modular exponentiation + 1 modular inverse
- **Sign**: 1 modular exponentiation + modular inverse
- **Verify**: 2 modular exponentiations

## Troubleshooting

### Common Issues

#### 1. OpenSSL Not Found

```
Error: Could not find OpenSSL
```

**Solution**: Set OpenSSL path explicitly:

```bash
cmake -DOPENSSL_ROOT_DIR=C:/OpenSSL ..
```

#### 2. Missing DLL

```
The program can't start because libcrypto-3-x64.dll is missing
```

**Solution**: Add OpenSSL bin directory to PATH or copy DLL to executable directory

#### 3. PRNG Not Seeded

```
PRNG not sufficiently seeded!
```

**Solution**: On Windows, OpenSSL automatically seeds from system entropy. If this error occurs, ensure you have proper system entropy sources.

#### 4. Linker Errors

```
unresolved external symbol BN_new
```

**Solution**: Make sure to link against libcrypto:

- MSVC: Add `libcrypto.lib`
- MinGW: Add `-lcrypto`

## API Reference

### ElGamalKey Class

```cpp
class ElGamalKey {
public:
    BN_ptr p;           // Prime modulus
    BN_ptr g;           // Generator
    BN_ptr h;           // Public key (h = g^x mod p)
    BN_ptr x;           // Private key (secret exponent)

    bool hasPrivateKey() const;
};
```

### ElGamal Class Methods

#### generateKey()

```cpp
bool generateKey(ElGamalKey& key, int bits);
```

Generate ElGamal key pair with specified bit length.

**Parameters:**

- `key`: Reference to ElGamalKey to populate
- `bits`: Key size in bits (1024, 2048, 3072, 4096)

**Returns:** `true` on success, `false` on failure

#### encrypt()

```cpp
bool encrypt(const ElGamalKey& key, const BIGNUM* message,
             ElGamalCiphertext& ciphertext);
```

Encrypt a message using ElGamal encryption.

**Parameters:**

- `key`: Public key
- `message`: Plaintext (must be < p)
- `ciphertext`: Output ciphertext

**Returns:** `true` on success, `false` on failure

#### decrypt()

```cpp
bool decrypt(const ElGamalKey& key, const ElGamalCiphertext& ciphertext,
             BIGNUM* message);
```

Decrypt a ciphertext using ElGamal decryption.

**Parameters:**

- `key`: Private key (must contain x)
- `ciphertext`: Ciphertext to decrypt
- `message`: Output plaintext

**Returns:** `true` on success, `false` on failure

#### sign()

```cpp
bool sign(const ElGamalKey& key, const unsigned char* msg, size_t msg_len,
          BIGNUM* r, BIGNUM* s);
```

Generate ElGamal signature.

**Parameters:**

- `key`: Private key (must contain x)
- `msg`: Message bytes to sign
- `msg_len`: Length of message
- `r`: Output signature component r
- `s`: Output signature component s

**Returns:** `true` on success, `false` on failure

#### verify()

```cpp
bool verify(const ElGamalKey& key, const unsigned char* msg, size_t msg_len,
            const BIGNUM* r, const BIGNUM* s);
```

Verify ElGamal signature.

**Parameters:**

- `key`: Public key
- `msg`: Message bytes
- `msg_len`: Length of message
- `r`: Signature component r
- `s`: Signature component s

**Returns:** `true` if valid, `false` if invalid

## Testing

The implementation includes three test functions:

1. **demo_encryption()**: Tests encryption/decryption correctness
2. **demo_signature()**: Tests signature generation and verification
3. **demo_homomorphic()**: Demonstrates multiplicative homomorphism

## Advanced Usage

### Saving/Loading Keys

```cpp
// Save public key to file
FILE* fp = fopen("public_key.txt", "w");
BN_print_fp(fp, key.p.get());
fprintf(fp, "\n");
BN_print_fp(fp, key.g.get());
fprintf(fp, "\n");
BN_print_fp(fp, key.h.get());
fclose(fp);

// Load public key from file
BN_ptr p = make_bn();
BN_ptr g = make_bn();
BN_ptr h = make_bn();
// Use BN_dec2bn or BN_hex2bn to read values
```

### Hybrid Encryption (ElGamal + AES)

```cpp
// 1. Generate random AES key
unsigned char aes_key[32];
RAND_bytes(aes_key, 32);

// 2. Convert AES key to BIGNUM
BN_ptr key_bn = make_bn();
BN_bin2bn(aes_key, 32, key_bn.get());

// 3. Encrypt AES key with ElGamal
ElGamalCiphertext encrypted_key;
elgamal.encrypt(pubkey, key_bn.get(), encrypted_key);

// 4. Encrypt actual data with AES
// (Use OpenSSL EVP API for AES encryption)

// 5. Send: encrypted_key + aes_encrypted_data
```

### Batch Operations

```cpp
// Encrypt multiple messages efficiently
std::vector<ElGamalCiphertext> ciphertexts;
std::vector<BN_ptr> messages = {/* ... */};

for (const auto& msg : messages) {
    ElGamalCiphertext ct;
    elgamal.encrypt(key, msg.get(), ct);
    ciphertexts.push_back(std::move(ct));
}
```

## Integration with Other Projects

### As a Static Library

Add to your CMakeLists.txt:

```cmake
add_library(elgamal STATIC elgamal_implementation.cpp)
target_link_libraries(elgamal PUBLIC OpenSSL::Crypto)

# In your project:
target_link_libraries(your_project PRIVATE elgamal)
```

### As a Header-Only Library

Extract the ElGamal class to a header file and mark functions as `inline`.

## Contributing

Feel free to extend this implementation with:

- Threshold ElGamal
- Elliptic curve variant (EC-ElGamal)
- Optimized parameter generation
- Additional padding schemes
- GUI interface

## References

1. ElGamal, T. (1985). "A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms"
2. Menezes, A., et al. (1996). "Handbook of Applied Cryptography"
3. OpenSSL Documentation: https://www.openssl.org/docs/

## License

This implementation is provided for educational and research purposes. Ensure proper security audit before production use.

## Notes

This implementation demonstrates:

- ✅ Modern C++ practices (RAII, smart pointers)
- ✅ Proper OpenSSL memory management
- ✅ Comprehensive error handling
- ✅ Clear, readable code structure
- ✅ Educational demonstrations

For production use, consider:

- Additional security hardening
- Formal security audit
- Side-channel attack mitigation
- Compliance with cryptographic standards

---

