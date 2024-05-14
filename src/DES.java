/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package crypto;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class DES {
		
	//Permuted Choice 1
	private static int[] PC1 = 
	{  
		57, 49, 41, 33, 25, 17,  9,
		1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4
	};
	
	// Left Shifts
	private static int[] KEY_SHIFTS = {0,  1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1};
	
	//Permuted Choice 2
	private static int[] PC2 = 
	{
		14, 17, 11, 24,  1,  5,
		3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
	};
	
	// Expansion Function1
	private static int[][] s1 = {
		{14, 4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,  9,  5,  3,  8},
		{4, 1, 14,  8, 13,  6, 2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
	};

	// Expansion Function2
	private static int[][] s2 = {
			{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			{3, 13,  4, 7, 15,  2,  8, 14, 12,  0, 1, 10,  6,  9, 11,  5},
			{0, 14, 7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
			{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14,  9}
		};
	
	// Expansion Function3
	private static int[][] s3 = {
			{10, 0, 9, 14, 6, 3, 15, 5,  1, 13, 12, 7, 11, 4, 2,  8},
			{13, 7, 0, 9, 3,  4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
			{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14,  7},
			{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
		};
	
	// Expansion Function4
	private static int[][] s4 = {
			{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
			{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14,  9},
			{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
			{3, 15, 0, 6, 10, 1, 13, 8, 9,  4, 5, 11, 12, 7, 2, 14}
		};
	
	// Expansion Function5
	private static int[][] s5 = {
			{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
			{14, 11, 2, 12,  4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
			{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
			{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
		};
	
	// Expansion Function6
	private static int[][] s6 = {
			{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
			{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
			{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
			{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
		};
	
	// Expansion Function7
	private static int[][] s7 = {
			{4, 11, 2, 14, 15,  0, 8, 13 , 3, 12, 9 , 7,  5, 10, 6, 1},
			{13 , 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
			{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
			{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
		};

	// Expansion Function8
	private static int[][] s8 = {
			{13, 2, 8,  4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
			{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6 ,11, 0, 14, 9, 2},
			{7, 11, 4, 1, 9, 12, 14, 2,  0, 6, 10 ,13, 15, 3, 5, 8},
			{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6 ,11}
		};

	// Initial Permutation
	static int[] IP = 
	{
		58, 50, 42, 34, 26, 18, 10 , 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
	};

	// Inverse Initial Permutation
	static int[] IPi = 
	{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43 ,11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25
	};
	
                
	// Expansion Table for the expansion function
private static int[] expansionTable = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// Permutation Function
		static int[] p = 
	{
		16,  7, 20, 21,29, 12, 28, 17, 
		1, 15, 23, 26, 5, 18, 31, 10, 
		2,  8, 24, 14, 32, 27,  3,  9, 
		19, 13, 30,  6, 22, 11,  4, 25
	};

// Declartion of arrays that contain the keys from k0 to k16
static String[] FinalKeys = new String[17];

// Key OF DES
// 1- Apply PC-1 (Permutation Choice 1) to convert the 64-bit key to 56-bit key.
// 2- Make The 56-bit key into halves, C0 and D0.
// 3- Apply the 16 rounds of shifting and compression to C0 and D0 to get C16 and D16.
// 4- Collect From C1 and D1 to C16 and D16 in order of C and D to get 56-bit key.
// 5- Apply PC-2 (Permutation Choice 2) to convert the 56-bit key to 48-bit key for each key and now we have 16 keys for 16 rounds.

// Plaintext
// Encrypting the plaintext using the key of DES.
// 1- Apply IP (Initial Permutation) to the plaintext.
// 2- Make The 64-bit plaintext into halves, L0 and R0.
// 3- Apply the 16 rounds of DES to L0 and R0 to get L16 and R16.
// The Main Equation of DES = L(i) = R(i-1) and R(i) = L(i-1) XOR f(R(i-1), K(i))
// Where f is the function of DES and K(i) is the key for the i-th round.
// Here is the steps :
//     1- Apply E (Expansion Permutation) to convert the 32-bit to 48-bit. 
//     2- XOR the 48-bit with the 48-bit key K(i).
//     3- Apply S-boxes (Substitution Boxes that doing it in 8 steps, each step is reducing 6-bit to 4-bit.) to convert the 48-bit to 32-bit.
//     4- Apply P (Permutation) for the 32-bit and this is the final result of the function.
//     5- XOR the 32-bit that we get from the function with the 32-bit of L(i-1).
// 4- After the 16 rounds, we have L16 and R16 and we put them in the reverse order to get R16L16.
// 5- Apply IP-1 (Inverse Initial Permutation) to get the final result of the plaintext.

// function to convert from hex to binary
public static String hexToBinary(String hex) {
	String binary = new BigInteger(hex, 16).toString(2);
	while (binary.length() < hex.length() * 4) {
		binary = "0" + binary;
	}
	return binary;
}

// function to convert from binary to hex
public static String binaryToHex(String binary) {
	String hex = new BigInteger(binary, 2).toString(16);
	while (hex.length() < binary.length() / 4) {
		hex = "0" + hex;
	}
	return hex;
}

// function to convert from text to binary
public static String textToBinary(String text) throws UnsupportedEncodingException {
	byte[] bytes = text.getBytes("UTF-8");
	StringBuilder binary = new StringBuilder();
	for (byte b : bytes) {
		int val = b;
		for (int i = 0; i < 8; i++) {
			binary.append((val & 128) == 0 ? 0 : 1);
			val <<= 1;
		}
	}
	return binary.toString();
}

// function to convert from binary to text
public static String binaryToText(String binary) {
	StringBuilder text = new StringBuilder();
	for (int i = 0; i < binary.length(); i += 8) {
		int charCode = Integer.parseInt(binary.substring(i, i + 8), 2);
		text.append((char) charCode);
	}
	return text.toString();
}

// function to apply the Permutation Choice 1 (PC-1) to convert the 64-bit key to 56-bit key.
public static String applyPC1(String key) {
	String key56 = "";
	for (int i = 0; i < PC1.length; i++) {
		key56 += key.charAt(PC1[i] - 1);
	}
	return key56;
}

// function to apply the Permutation Choice 2 (PC-2) to convert the 56-bit key to 48-bit key.
public static String applyPC2(String key) {
	String key48 = "";
	for (int i = 0; i < PC2.length; i++) {
		key48 += key.charAt(PC2[i] - 1);
	}
	return key48;
}

// function to half the key
public static String[] halfKey(String key) {
	String[] keys = new String[2];
	keys[0] = key.substring(0, key.length() / 2);
	keys[1] = key.substring(key.length() / 2);
	return keys;
}

// function to collect the key
public static String collectKey(String[] keys) {
	return keys[0] + keys[1];
}

// function to shift the key
public static String shiftKey(String key, int shift) {
	String shiftedKey = "";
	for (int i = 0; i < key.length(); i++) {
		shiftedKey += key.charAt((i + shift) % key.length());
	}
	return shiftedKey;
}

// function of make the key of DES
public static void makeKey(String key) {
	String key64 = hexToBinary(key);
	String key56 = applyPC1(key64);
	String[] keys = halfKey(key56);
	for (int i = 0; i < 17; i++) {
		keys[0] = shiftKey(keys[0], KEY_SHIFTS[i]);
		keys[1] = shiftKey(keys[1], KEY_SHIFTS[i]);
		FinalKeys[i] = applyPC2(collectKey(keys));
	}
}

// function to apply Initial Permutation (IP) to the plaintext
public static String applyIP(String plaintext) {
	String ip = "";
	for (int i = 0; i < IP.length; i++) {
		ip += plaintext.charAt(IP[i] - 1);
	}
	return ip;
}

// function to apply Inverse Initial Permutation (IP-1) to the plaintext
public static String applyIPi(String plaintext) {
	String ipi = "";
	for (int i = 0; i < IPi.length; i++) {
		ipi += plaintext.charAt(IPi[i] - 1);
	}
	return ipi;
}

// function to apply Expansion Permutation (E) to convert the 32-bit to 48-bit
public static String applyExpansion(String right) {
	String expanded = "";
	for (int i = 0; i < expansionTable.length; i++) {
		expanded += right.charAt(expansionTable[i] - 1);
	}
	return expanded;
}

// function to apply Permutation (P) for the 32-bit
public static String applyPermutation(String right) {
	String permuted = "";
	for (int i = 0; i < p.length; i++) {
		permuted += right.charAt(p[i] - 1);
	}
	return permuted;
}

// function to apply the S-boxes
public static String applySBoxes(String right) {
	String sBoxed = "";
	for (int i = 0; i < 8; i++) {
		String sBox = right.substring(i * 6, (i + 1) * 6);
		int row = Integer.parseInt(sBox.charAt(0) + "" + sBox.charAt(5), 2);
		int col = Integer.parseInt(sBox.substring(1, 5), 2);
		int sBoxValue = 0;
		switch (i) {
			case 0:
				sBoxValue = s1[row][col];
				break;
			case 1:
				sBoxValue = s2[row][col];
				break;
			case 2:
				sBoxValue = s3[row][col];
				break;
			case 3:
				sBoxValue = s4[row][col];
				break;
			case 4:
				sBoxValue = s5[row][col];
				break;
			case 5:
				sBoxValue = s6[row][col];
				break;
			case 6:
				sBoxValue = s7[row][col];
				break;
			case 7:
				sBoxValue = s8[row][col];
				break;
		}
		String sBoxBinary = Integer.toBinaryString(sBoxValue);
		while (sBoxBinary.length() < 4) {
			sBoxBinary = "0" + sBoxBinary;
		}
		sBoxed += sBoxBinary;
	}
	return sBoxed;
}

// function that apply xor operation
public static String applyXOR(String a, String b) {
	String xor = "";
	for (int i = 0; i < a.length(); i++) {
		xor += a.charAt(i) == b.charAt(i) ? "0" : "1";
	}
	return xor;
}

// function to apply the function of DES for the 16 rounds for left and right parts from the plaintext
//DES = L(i) = R(i-1) and R(i) = L(i-1) XOR f(R(i-1), K(i))
public static String applyDesFunction(String left, String right, String key) {
	String expanded = applyExpansion(right);
	String xor = applyXOR(expanded, key);
	String sBoxed = applySBoxes(xor);
	String permuted = applyPermutation(sBoxed);
	return applyXOR(left, permuted);
}

// function to apply the 16 rounds of DES
public static String applyDesRounds(String plaintext, boolean encrypt) {
	// half the plaintext
	String[] parts = halfKey(plaintext);
	// apply the 16 rounds of DES starting from the second round
	for (int i = 1; i < 17; i++) {
		String temp = parts[1];
		if (encrypt) {
			parts[1] = applyDesFunction(parts[0], parts[1], FinalKeys[i]);
		} else {
			parts[1] = applyDesFunction(parts[0], parts[1], FinalKeys[17 - i]);
		}
		parts[0] = temp;
	}
	// reverse the parts
	String reversed = parts[1] + parts[0];
	return reversed;
}

// function to encrypt the plaintext using the key of DES
public static String encrypt(String plaintext) {

	// convert the plaintext to binary
	String binary = hexToBinary(plaintext);

	// apply the Initial Permutation (IP) to the plaintext
	String ip = applyIP(binary);

	// apply the 16 rounds of DES
	String des = applyDesRounds(ip, true);

	// apply the Inverse Initial Permutation (IP-1) to the plaintext
	String ipi = applyIPi(des);

	// convert the binary to hex
	String hex = binaryToHex(ipi);
	return hex;
}

// function to decrypt the ciphertext using the key of DES
public static String decrypt(String ciphertext) {

	// convert the ciphertext to binary
	String binary = hexToBinary(ciphertext);

	// apply the Initial Permutation (IP) to the ciphertext
	String ip = applyIP(binary);

	// apply the 16 rounds of DES
	String des = applyDesRounds(ip, false);

	// apply the Inverse Initial Permutation (IP-1) to the ciphertext
	String ipi = applyIPi(des);

	// convert the binary to hex
	String hex = binaryToHex(ipi);

	return hex;
}


	// Main Function
	public static void main(String[] args) throws UnsupportedEncodingException
	{
		String plaintext = "0123456789ABCDEF";
		String key = "133457799BBCDFF1";

		// Make the key of DES
		makeKey(key);

		// Encrypt the plaintext using the key of DES
		String ciphertext = encrypt(plaintext);

		// Decrypt the ciphertext using the key of DES
		String decrypted = decrypt(ciphertext);

		// Print the Ciphertext
		System.out.println("Ciphertext: " + ciphertext);

		// Print the Decrypted
		System.out.println("Decrypted: " + decrypted);
	}
}