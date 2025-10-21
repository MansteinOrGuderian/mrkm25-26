# ElGamal Cryptosystem Implementation

A secure implementation of the ElGamal public-key cryptosystem in C++17 using OpenSSL, with PKCS#1 v1.5 padding and comprehensive security testing.

## Features

- **ElGamal Key Generation**: 1024/2048/4096-bit safe prime generation
- **PKCS#1 v1.5 Padding**: Standard-compliant encryption padding
- **Key Import/Export**: PEM format for key persistence
- **Security Testing Framework**: 7 comprehensive security tests
- **Interactive Demo Mode**: User-friendly demonstration interface

## Security Tests Included

1. ✅ Basic Encryption/Decryption Functionality
2. ✅ Timing Attack Resistance Analysis
3. ✅ Memory Safety Analysis
4. ✅ Key Export/Import (PKCS-style PEM)
5. ✅ Randomness Quality (Ephemeral Key Generation)
6. ✅ OS Protection Mechanism Analysis
7. ✅ Input Validation and Error Handling

## Requirements

- **C++17** compatible compiler
- **OpenSSL 1.1.1+** or **OpenSSL 3.x**
- **Windows** (for OS-specific tests) or cross-platform (core functionality)

## Project Structure
```
├─── SourceCode
│   ├── Header.h              # ElGamal class declarations and structures
│   ├── ElGamalSource.cpp     # Core ElGamal implementation
│   └── lab4.cpp              # Security testing framework and main program
├── *.tex
├── Report_lab4.pdf
└── README.md             
```

## Building and Running

### Option 1: Visual Studio 2019 (Windows)

#### Setup
1. Open Visual Studio 2019
2. Create a new **Console Application** project
3. Add all source files to the project
4. Configure OpenSSL:
   - Install OpenSSL (e.g., via [vcpkg](https://github.com/microsoft/vcpkg))
   - Or download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html)

#### Configure OpenSSL in VS

**Project Properties** → **Configuration Properties**:

1. **C/C++** → **General** → **Additional Include Directories**:
```
   C:\Program Files\OpenSSL-Win64\include
```

2. **Linker** → **General** → **Additional Library Directories**:
```
   C:\Program Files\OpenSSL-Win64\lib
```

3. **Linker** → **Input** → **Additional Dependencies**, add:
```
   libcrypto.lib
   libssl.lib
```

#### Run Security Tests
1. Build the project: **Ctrl+Shift+B**
2. Run: **F5** or **Ctrl+F5**

#### Run Interactive Demo Mode
1. Right-click project → **Properties**
2. **Configuration Properties** → **Debugging**
3. **Command Arguments**: `--demo`
4. Click **OK**
5. Run: **F5** or **Ctrl+F5**

### Option 2: MinGW with VS Code (Windows/Linux)

#### Setup OpenSSL

**Windows (MSYS2/MinGW64)**:
```bash
pacman -S mingw-w64-x86_64-openssl
```

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get install libssl-dev
```

#### Compile

**Windows (MinGW64)**:
```bash
g++ -std=c++17 ElGamalSource.cpp lab.cpp -o SourceCode.exe -lcrypto -lssl -lpsapi
```

**Linux/macOS**:
```bash
g++ -std=c++17 ElGamalSource.cpp lab.cpp -o SourceCode -lcrypto -lssl -lpthread
```

#### Run

**Security Tests**:
```bash
./SourceCode
```

**Interactive Demo**:
```bash
./SourceCode --demo
```

### Option 3: VS Code with tasks.json

Create `.vscode/tasks.json`:
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build SourceCode",
            "type": "shell",
            "command": "g++",
            "args": [
                "-std=c++17",
                "ElGamalSource.cpp",
                "lab.cpp",
                "-o",
                "SourceCode",
                "-lcrypto",
                "-lssl",
                "-lpthread"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}
```

Create `.vscode/launch.json` for debugging:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug ElGamal Tests",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/SourceCode",
            "args": [],
            "cwd": "${workspaceFolder}",
            "preLaunchTask": "Build SourceCode"
        },
        {
            "name": "Debug ElGamal Demo",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/SourceCode",
            "args": ["--demo"],
            "cwd": "${workspaceFolder}",
            "preLaunchTask": "Build SourceCode"
        }
    ]
}
```

Then:
- Press **Ctrl+Shift+B** to build
- Press **F5** to run/debug

## Usage Examples

### Generate Keys and Encrypt
```cpp
#include "Header.h"

int main() {
    // Generate 2048-bit key pair
    auto [publicKey, privateKey] = ElGamalCrypto::generateKeyPair(2048);
    
    // Encrypt message
    std::string message = "Hello, ElGamal!";
    std::vector msg(message.begin(), message.end());
    ElGamalCiphertext ciphertext = ElGamalCrypto::encrypt(msg, publicKey);
    
    // Decrypt message
    std::vector decrypted = ElGamalCrypto::decrypt(ciphertext, privateKey);
    std::string result(decrypted.begin(), decrypted.end());
    
    std::cout << "Decrypted: " << result << std::endl;
    return 0;
}
```

### Export/Import Keys
```cpp
// Export keys to PEM format
std::string publicPEM = ElGamalCrypto::exportPublicKeyToPEM(publicKey);
std::string privatePEM = ElGamalCrypto::exportPrivateKeyToPEM(privateKey);

// Save to files
std::ofstream("public.pem") << publicPEM;
std::ofstream("private.pem") << privatePEM;

// Import keys from PEM
ElGamalPublicKey importedPub = ElGamalCrypto::importPublicKeyFromPEM(publicPEM);
ElGamalPrivateKey importedPriv = ElGamalCrypto::importPrivateKeyFromPEM(privatePEM);
```

## Output Files

After running, the following files are generated:

- `elgamal_security_test.log` - Detailed security test results
- `elgamal_public.pem` - Exported public key (Test 4)
- `elgamal_private.pem` - Exported private key (Test 4)
- `elgamal_demo_public.pem` - Demo mode public key
- `elgamal_demo_private.pem` - Demo mode private key

## Security Considerations

### Strengths
- ✅ Safe prime generation (p = 2q + 1)
- ✅ PKCS#1 v1.5 padding prevents simple attacks
- ✅ Cryptographically secure random number generation
- ✅ Proper input validation and error handling
- ✅ No duplicate ephemeral keys (good RNG quality)

### Limitations
- ⚠️ Not constant-time (vulnerable to sophisticated timing attacks)
- ⚠️ PKCS#1 v1.5 padding (consider OAEP for production)
- ⚠️ No key authentication (vulnerable to MITM without PKI)
- ⚠️ Educational implementation (use established libraries for production)

## Algorithm Overview

**Key Generation**:
1. Generate safe prime p = 2q + 1 where q is prime
2. Find generator g of the multiplicative group
3. Choose random private key x ∈ [1, p-2]
4. Compute public key y = g^x mod p

**Encryption** (message m):
1. Apply PKCS#1 v1.5 padding to m
2. Choose random ephemeral key k ∈ [1, p-2]
3. Compute c1 = g^k mod p
4. Compute c2 = m · y^k mod p
5. Ciphertext = (c1, c2)

**Decryption** (ciphertext (c1, c2)):
1. Compute s = c1^x mod p
2. Compute s^(-1) mod p
3. Compute m = c2 · s^(-1) mod p
4. Remove PKCS#1 v1.5 padding

## Troubleshooting

### OpenSSL Linking Errors
- Ensure OpenSSL is installed and paths are correctly configured
- On Windows, you may need to copy OpenSSL DLLs to your executable directory

### "Access violation" or Crashes
- Verify key size is at least 1024 bits
- Check that messages aren't too large for the key size

### All Tests Fail with Padding Errors
- Ensure you're using the fixed `decrypt()` function with proper block size handling

## License

Educational project for cryptography learning purposes.

## Author

Developed as part of a cryptographic systems security analysis project.

## References

- [ElGamal Encryption - Wikipedia](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [PKCS #1: RSA Cryptography Specifications](https://tools.ietf.org/html/rfc8017)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
