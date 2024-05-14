package crypto;

public class AES {

    // S-Box Tables
    private static final int[][] sBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };

    // Inverse S-Box Tables
    private static final int[][] invSBox = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    // Round Constant
    private static final int[] rCon = {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // Mix Columns Matrix
    private static final int[][] mixColumnsMatrix = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
    };

    // Inverse Mix Columns Matrix
    private static final int[][] invMixColumnsMatrix = {
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e}
    };

    // AES Variable that contains all the 44 words of the key
    private static byte[][] expandedKey = new byte[4][44];


    /*
    Steps of AES Key Expansion

    The key expansion process is divided into several steps. The steps are as follows:

    Step 1: The first step is to create a key schedule. The key schedule is a 4×4 matrix that contains the original key. The key schedule is created by copying the original key into the first 4×4 matrix.
    Step 2: The second step is to create a new key schedule. The new key schedule is created by taking the last column of the key schedule and performing a series of operations on it. The operations are as follows:
        Rotate the last column by one byte to the left.
        Substitute each byte in the last column using the S-Box.
        XOR the first byte in the last column with a round constant.
    Step 3: The third step is to create a new key schedule. The new key schedule is created by taking the last column of the new key schedule and performing a series of operations on it. The operations are the same as in step 2.
    Step 4: Repeat steps 2 and 3 until the key schedule is the desired length.
    */

    /*
    The encryption process of AES consists of several steps. The steps are as follows:

    We have 10 rounds for this encryption process.
        Round 1 : In the first round, we perform the following operations:
            Step 1: Convert the input plaintext from block to a 4×4 matrix called the state matrix.
            Step 2: XOR the first round key (the original key from word 0 to word 3) to the state matrix.
            Step 3: Perform the SubBytes operation on the state matrix after what we did in step 2.
                In the SubBytes operation, each byte in the state matrix is substituted with a corresponding byte from the S-Box.
            Step 4: Perform the ShiftRows operation on the state matrix after what we did in step 3.
                In the ShiftRows operation, the first row of the state matrix is left unchanged,
                the second row is shifted one byte to the left,
                the third row is shifted two bytes to the left, and
                the fourth row is shifted three bytes to the left.
            Step 5: Perform the MixColumns operation on the state matrix after what we did in step 3.
                In the MixColumns operation, each column of the state matrix is multiplied by a fixed matrix.
        Round 2 : In the second round, we perform the following operations on the state matrix we got from the first round:
            Step 1: XOR the second round key (word 4 to word 7) to the state matrix.
            Step 2: Perform the SubBytes operation on the state matrix.
            Step 3: Perform the ShiftRows operation on the state matrix.
            Step 4: Perform the MixColumns operation on the state matrix.
        And so on for until the 10th round.

        In the 10th round, we got the final state matrix and convert it to a block to get the ciphertext.
    */


// Function that take hex string and return 4x4 matrix of bytes 
public static byte[][] createMatrix(String key) {
    byte[][] keyMatrix = new byte[4][4];
    int index = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keyMatrix[j][i] = (byte) Integer.parseInt(key.substring(index, index + 2), 16);
            index += 2;
        }
    }
    return keyMatrix;
}

// Function to take 4x4 matrix of bytes and return hex string which every coulmn is a word in the key so we take 4 words and concatenate them to get the key
public static String keyMatrixToString(byte[][] keyMatrix) {
    StringBuilder keyString = new StringBuilder();
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keyString.append(String.format("%02x", keyMatrix[j][i]));
        }
    }
    return keyString.toString();
}

// Function For shifting lift
public static byte[] shiftLeft(byte[] word, int count) {
    byte[] temp = new byte[word.length];
    for (int i = 0; i < word.length; i++) {
        temp[i] = word[(i + count) % word.length];
    }
    return temp;
}

// Function For Shifting Rows for Encryption
public static byte[][] shiftRowsforEncryption(byte[][] stateMatrix) {
    // Shift the second row one byte to the left
    stateMatrix[1] = shiftLeft(stateMatrix[1], 1);
    // Shift the third row two bytes to the left
    stateMatrix[2] = shiftLeft(stateMatrix[2], 2);
    // Shift the fourth row three bytes to the left
    stateMatrix[3] = shiftLeft(stateMatrix[3], 3);

    return stateMatrix;
}

// Function For Shifting Rows for Decryption
public static byte[][] shiftRowsforDecryption(byte[][] stateMatrix) {
    // Shift the second row one byte to the right
    stateMatrix[1] = shiftLeft(stateMatrix[1], 3);
    // Shift the third row two bytes to the right
    stateMatrix[2] = shiftLeft(stateMatrix[2], 2);
    // Shift the fourth row three bytes to the right
    stateMatrix[3] = shiftLeft(stateMatrix[3], 1);

    return stateMatrix;
}

// Function For Substituting bytes using S-Box
public static byte[] subBytes(byte[] word) {
    for (int i = 0; i < 4; i++) {
        int row = (word[i] & 0xf0) >> 4;
        int col = word[i] & 0x0f;
        word[i] = (byte) sBox[row][col];
    }
    return word;
}

// Function For Inverse Substituting bytes using Inverse S-Box
public static byte[] invSubBytes(byte[] word) {
    for (int i = 0; i < 4; i++) {
        int row = (word[i] & 0xf0) >> 4;
        int col = word[i] & 0x0f;
        word[i] = (byte) invSBox[row][col];
    }
    return word;
}

// Function to get round constant
public static byte[] getRcon(int round) {
    byte[] rCon = new byte[4];
    rCon[0] = (byte) AES.rCon[round - 1];
    for (int i = 1; i < 4; i++) {
        rCon[i] = 0x00;
    }
    return rCon;
}

// Function For XORing
public static byte[] xor(byte[] first, byte[] second) {
    for (int i = 0; i < 4; i++) {
        first[i] ^= second[i];
    }
    return first;
}

// Function For Mix Columns
public static byte[][] mixColumns(byte[][] stateMatrix) {
    byte[][] tempMatrix = new byte[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                tempMatrix[i][j] ^= multiply(mixColumnsMatrix[i][k], stateMatrix[k][j]);
            }
        }
    }
    return tempMatrix;
}

// Function For Inverse Mix Columns
public static byte[][] invMixColumns(byte[][] stateMatrix) {
    byte[][] tempMatrix = new byte[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                tempMatrix[i][j] ^= multiply(invMixColumnsMatrix[i][k], stateMatrix[k][j]);
            }
        }
    }
    return tempMatrix;
}

// Function For Multiplying two bytes
public static byte multiply(int a, byte b) {
    byte temp = 0;
    for (int i = 0; i < 8; i++) {
        if ((a & 0x01) == 1) {
            temp ^= b;
        }
        boolean highBit = (b & 0x80) == 0x80;
        b <<= 1;
        if (highBit) {
            b ^= 0x1b;
        }
        a >>= 1;
    }
    return temp;
}

// Function For Key Expansion using AES Algorithm
public static String keyExpansion(String key) {
    // Create a 4x4 matrix to store the key
    byte[][] keyMatrix = createMatrix(key);

    // Copy the key into the first 4 columns of the expanded key
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            expandedKey[i][j] = keyMatrix[i][j];
        }
    }

    // Generate the rest of the expanded key
    for (int i = 4; i < 44; i++) {
        // Get the previous word
        byte[] prevWord = new byte[4];

        for (int j = 0; j < 4; j++) {
            prevWord[j] = expandedKey[j][i - 1];
        }

        // Perform key schedule operations
        if (i % 4 == 0) {
            // Rotate the word
            prevWord = shiftLeft(prevWord, 1);

            // Substitute the bytes
            prevWord = subBytes(prevWord);

            // XOR with the round constant
            byte[] rCon = getRcon(i / 4);
            
            // print round constant
            // System.out.println("Round Constant " + i / 4 + ": " + String.format("%02x", rCon[0]));
            // XOR with the previous word
            prevWord = xor(prevWord, rCon);
        }

        // XOR with the previous word
        for (int j = 0; j < 4; j++) {
            expandedKey[j][i] = (byte) (expandedKey[j][i - 4] ^ prevWord[j]);
        }

        /* For Debugging
            print each round key matrix with separator
            if (i % 4 == 0) {
                System.out.println("Round Key " + i / 4 + ":");
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        System.out.print(String.format("%02x", expandedKey[j][i - 4 + k]) + " ");
                    }
                    System.out.println();
                }
                System.out.println();
            }
        */
        
    }

    // final matrix
    byte[][] finalMatrix = new byte[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            finalMatrix[j][i] = expandedKey[i][40 + j];
        }
    }


    // Print the finalMatrix
    // System.out.println("Final Matrix:");
    // for (int i = 0; i < 4; i++) {
    //     for (int j = 0; j < 4; j++) {
    //         System.out.print(String.format("%02x", finalMatrix[j][i]) + " ");
    //     }
    //     System.out.println();
    // }

    // Convert the expanded key to a hex string
    String expandedKeyString = keyMatrixToString(finalMatrix);

    return expandedKeyString;
}

// Encrypt the plaintext using AES Algorithm
public static String encrypt(String plaintext) {
    // Create a 4x4 matrix to store the plaintext
    byte[][] stateMatrix = createMatrix(plaintext);

    // Start the rounds of encryption
    for (int round = 0; round < 10; round++) {
        
        /* For Debugging
            State Matrix before XORing with the round key
            System.out.println("State Matrix before XOR with Round Key " + round + ":");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.print(String.format("%02x", stateMatrix[j][i]) + " ");
                }
                System.out.println();
            }

            XOR key matrix of the words that are in the round
            create a temporary matrix to store the key matrix of the round
            byte[][] keyMatrix = new byte[4][4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    keyMatrix[j][i] = expandedKey[j][4 * round + i];
                }
            }

            print the key matrix of the round
            System.out.println("Key Matrix of Round " + round + ":");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.print(String.format("%02x", keyMatrix[j][i]) + " ");
                }
                System.out.println();
            }
        */

        // XOR the state matrix with the round key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[j][i] ^= expandedKey[j][4 * round + i];
            }
        }

        /* For Debugging
            Print the state matrix after XORing with the round key
            System.out.println("State Matrix after XOR with Round Key " + round + ":");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.print(String.format("%02x", stateMatrix[i][j]) + " ");
                }
                System.out.println();
            }
            System.out.println();
        */

        // Perform the SubBytes operation
        for (int i = 0; i < 4; i++) {
            stateMatrix[i] = subBytes(stateMatrix[i]);
        }

        /* For Debugging
            Print the state matrix after SubBytes operation
            System.out.println("State Matrix after SubBytes:");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.print(String.format("%02x", stateMatrix[i][j]) + " ");
                }
                System.out.println();
            }
            System.out.println();
        */

        // Perform the ShiftRows operation
        stateMatrix = shiftRowsforEncryption(stateMatrix);

        /* For Debugging
            Print the state matrix after ShiftRows operation
            System.out.println("State Matrix after ShiftRows:");
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    System.out.print(String.format("%02x", stateMatrix[i][j]) + " ");
                }
                System.out.println();
            }
            System.out.println();
        */

        // Perform the MixColumns operation
        if (round < 9) {
            stateMatrix = mixColumns(stateMatrix);

            /* For Debugging
                Print the state matrix after MixColumns operation
                System.out.println("State Matrix after MixColumns:");
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < 4; j++) {
                        System.out.print(String.format("%02x", stateMatrix[i][j]) + " ");
                    }
                    System.out.println();
                }
                System.out.println();
            */
        }
    }

    // XOR the state matrix with the final round key
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            stateMatrix[j][i] ^= expandedKey[j][40 + i];
        }
    }

    // print the final state matrix
    System.out.println("Final State Matrix:");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            System.out.print(String.format("%02x", stateMatrix[i][j]) + " ");
        }
        System.out.println();
    }

    // Convert the state matrix to a hex string
    String ciphertext = keyMatrixToString(stateMatrix);

    return ciphertext;
}

// Decrypt the ciphertext using AES Algorithm
public static String decrypt(String ciphertext) {
    // Create a 4x4 matrix to store the ciphertext
    byte[][] stateMatrix = createMatrix(ciphertext);

    // Inverse the final round key
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            stateMatrix[j][i] ^= expandedKey[j][40 + i];
        }
    }

    // Start the rounds of decryption
    for (int round = 9; round >= 0; round--) {
        // Perform the Inverse ShiftRows operation
        stateMatrix = shiftRowsforDecryption(stateMatrix);

        // Perform the Inverse SubBytes operation
        for (int i = 0; i < 4; i++) {
            stateMatrix[i] = invSubBytes(stateMatrix[i]);
        }

        // XOR key matrix of the words that are in the round
        // create a temporary matrix to store the key matrix of the round
        byte[][] keyMatrix = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                keyMatrix[j][i] = expandedKey[j][4 * round + i];
            }
        }

        // XOR the state matrix with the round key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateMatrix[j][i] ^= keyMatrix[j][i];
            }
        }

        // Perform the Inverse MixColumns operation
        if (round > 0) {
            stateMatrix = invMixColumns(stateMatrix);
        }
    }

    // Convert the state matrix to a hex string
    String plaintext = keyMatrixToString(stateMatrix);

    return plaintext;
}

// main function to test the key expansion
public static void main(String[] args) {
    String plaintext = "54776F204F6E65204E696E652054776F";
    String key = "5468617473206D79204B756E67204675";

    String expandedKeyString = keyExpansion(key);


    System.out.println("Expanded Key: " + expandedKeyString);

    String ciphertext = encrypt(plaintext);

    System.out.println("The Ciphertext: " + ciphertext);

    // print 44 words of the key
    // for (int i = 0; i < 44; i++) {
    //     System.out.println("Word " + i + ": " + String.format("%02x", expandedKey[0][i]) + " " + String.format("%02x", expandedKey[1][i]) + " " + String.format("%02x", expandedKey[2][i]) + " " + String.format("%02x", expandedKey[3][i]));
    // }

    String decryptedText = decrypt(ciphertext);

    System.out.println("The Decrypted Text: " + decryptedText);

}
}
