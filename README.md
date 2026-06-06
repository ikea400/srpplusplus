# SRP++ - Secure Remote Password Protocol Implementation

A modern C++ implementation of the Secure Remote Password (SRP) protocol, providing secure password-based authentication without transmitting passwords over the network.

## Overview

SRP++ is a C++ library that implements the Secure Remote Password protocol (SRP-6a), a cryptographically strong authentication protocol that:

- Prevents password disclosure during authentication
- Resists dictionary attacks and replay attacks
- Provides mutual authentication between client and server
- Doesn't require PKI (Public Key Infrastructure)

## Features

- **Modern C++ Design**: Uses C++17 features with RAII principles
- **Multiple Hash Algorithms**: SHA-1, SHA-2 (224/256/384/512), SHA-3 (224/256/384/512)
- **Flexible Key Sizes**: Supports key sizes from 1024 to 8192 bits
- **OpenSSL Integration**: Uses OpenSSL for cryptographic operations including BIGNUM implementations
- **Build System**: Currently uses Visual Studio project files (.vcxproj) for Windows builds

## Installation

### Prerequisites

- C++17 compatible compiler (MSVC recommended for current build system)
- OpenSSL development libraries
- Visual Studio 2022 or later (for .vcxproj files)

## Usage

### Basic Example

```cpp
#include "srp_client.h"
#include "srp_server.h"

// Client-side authentication
SRP::CSRPClient client(SRP::EHashAlgorithm::SHA256, SRP::ENGType::NG_2048);
client.Step1("username", "password", "salt_hex_string");
std::string clientPublicKey = client.GetPublicKey();

// Server-side authentication
SRP::CSRPServer server(SRP::EHashAlgorithm::SHA256, SRP::ENGType::NG_2048);
server.Step1("username", "salt_hex_string", "verifier_hex_string");
std::string serverPublicKey = server.GetPublicKey();

// Continue authentication protocol...
```

## API Documentation

### Client Class (`CSRPClient`)

- **Constructor**: `CSRPClient(EHashAlgorithm algorithm, ENGType type)`
- **Step 1**: Initialize with identity, password, and salt
- **Step 2**: Process server's public key
- **Step 3**: Verify server's evidence and complete authentication

### Server Class (`CSRPServer`)

- **Constructor**: `CSRPServer(EHashAlgorithm algorithm, ENGType type)`
- **Step 1**: Initialize with identity, salt, and verifier
- **Step 2**: Process client's public key
- **Step 3**: Generate evidence for client verification

## Security Considerations

- Always use the largest key size practical for your application
- Prefer SHA-256 or stronger hash algorithms
- Ensure proper random number generation for salts and private keys
- Store verifiers securely (they're equivalent to hashed passwords)

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Acknowledgments

- Based on the SRP protocol designed by Tom Wu
- Uses OpenSSL for cryptographic operations
- Inspired by various SRP implementations in other languages

## Contact

For questions or support, please contact the project maintainer.

---

© 2026 Natael Lavoie
