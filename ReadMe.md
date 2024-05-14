# Cryptography Algorithms

This Java project provides pure implementations without any external libraries of three widely used cryptographic algorithms: RSA, DES, and AES.

## Table of Contents

- [Introduction](#introduction)
- [RSA](#rsa)
- [DES](#des)
- [AES](#aes)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction

Cryptography is the practice of securing communication from adversaries. This project aims to provide a comprehensive implementation and educational resource for three popular cryptographic algorithms: RSA, DES, and AES.


## RSA

RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm widely used for secure data transmission. It involves the use of public and private keys for encryption and decryption using miller-rabin primality test to generate large prime numbers , you can find comments that explain the algorithm process and the code implementation in the RSA class.

## DES

DES (Data Encryption Standard) is a symmetric encryption algorithm that uses a 56-bit key to encrypt and decrypt data. It is widely used in various applications for secure data transmission , you can find comments that explain of key generation process in Key Of DES .md file and in the DES class you can find comments that explain the whole algorithm process and the code implementation and some debugging code to test every step of the algorithm, and There is a simple gui to test the algorithm.

## AES

AES (Advanced Encryption Standard) is a symmetric encryption algorithm that uses a variable-length key (128, 192, or 256 bits) to encrypt and decrypt data. It is considered one of the most secure encryption algorithms , you can find comments that explain the algorithm process and the code implementation in the AES class.

## Usage

To use this project, follow these steps:

1. Clone the repository: `git clone https://github.com/your-username/your-repo.git`
2. Open the project in your favorite Java IDE.
3. Explore the source code and find the implementation of the desired algorithm.
4. Use the provided classes and methods to encrypt and decrypt data using the chosen algorithm.

Please note that the code in this project operates with hexadecimal values only. If you need to work with other data formats, such as strings or integers, you will need to handle the conversion appropriately. Make sure to convert your data to hexadecimal format before using the provided classes and methods for encryption and decryption.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).