package crypto;
import java.math.BigInteger;

public class RSA {

    /*
    Steps OF RSA Key Generation:
        1. Choose two relatively prime numbers p and q.
        2. Compute n = p * q. (n is the modulus for the public key and the private keys)
        3. Compute the totient of n, φ(n) = (p-1)(q-1). (φ is the Euler's totient function)
        4. Choose an integer e such that
            1 < e < φ(n), and
            e is coprime to φ(n). (e is the public key exponent)
        5. Determine d as d ≡ e^(-1) (mod φ(n));
            d is the modular multiplicative inverse of e modulo φ(n). (d is the private key exponent)

    RSA Encryption:
        c = m^e mod n
        where,
            c = ciphertext
            m = plaintext
            e = public key exponent
            n = modulus

    RSA Decryption:
        m = c^d mod n
        where,
            m = plaintext
            c = ciphertext
            d = private key exponent
            n = modulus

    RSA Example:
        Let p = 61 and q = 53.
        Compute n = p * q = 61 * 53 = 3233.
        Compute φ(n) = (p-1)(q-1) = 60 * 52 = 3120.
        Choose e = 17.
        Compute d as d ≡ e^(-1) (mod φ(n)) = 2753.
        Public key (e, n) = (17, 3233).
        Private key (d, n) = (2753, 3233).
        Let m = 65.
        Encrypt m as c = m^e mod n = 2790.
        Decrypt c as m = c^d mod n = 65.
        The plaintext m = 65 is successfully encrypted and decrypted using RSA.
    */

    // declaration of variables
    public static BigInteger p, q, n, phi, e, d;

    // function to cumpute n = p * q
    public static void computeN() {
        n = p.multiply(q);
    }

    // function to compute φ(n) = (p-1)(q-1)
    public static void computePhi() {
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    // function to generate public and private keys
    public static void generateKeys() {
        // determine d as d ≡ e^(-1) (mod φ(n))
        d = e.modInverse(phi);
    }

    // function to encrypt plaintext
    public static BigInteger encrypt(BigInteger plaintext) {
        // c = m^e mod n
        return plaintext.modPow(e, n);
    }

    // function to decrypt ciphertext
    public static BigInteger decrypt(BigInteger ciphertext) {
        // m = c^d mod n
        return ciphertext.modPow(d, n);
    }

    // function to generate a random number and use miller rabin test to check if it's prime
    public static BigInteger generatePrime() {
        BigInteger num;
        do {
            num = new BigInteger(10, 1, new java.util.Random());
        } while (!MillerRabin.MillerRabinTest(num));
        return num;
    }

    // function to get e such that 1 < e < φ(n) and e is coprime to φ(n)
    public static BigInteger getE() {
        BigInteger e;
        do {
            e = new BigInteger(10, new java.util.Random());
        } while (e.compareTo(phi) != -1 || !e.gcd(phi).equals(BigInteger.ONE));
        return e;
    }

    // main function
    public static void main(String[] args) {

    // generate two prime numbers
    p = generatePrime();
    q = generatePrime();

    System.out.println("p = " + p);
    System.out.println("q = " + q);

    // compute n = p * q
    computeN();

    // compute φ(n) = (p-1)(q-1)
    computePhi();

    // choose e such that 1 < e < φ(n) and e is coprime to φ(n)
    e = getE();

    System.out.println("e = " + e);

    // generate public and private keys
    generateKeys();

    // display public and private keys
    System.out.println("Public key (e, n) = (" + e + ", " + n + ")");

    System.out.println("Private key (d, n) = (" + d + ", " + n + ")");

    // plaintext
    BigInteger plaintext = new BigInteger("65");

    System.out.println("Plaintext = " + plaintext);

    // encrypt plaintext
    BigInteger ciphertext = encrypt(plaintext);

    // display ciphertext
    System.out.println("Ciphertext = " + ciphertext);

    // decrypt ciphertext
    BigInteger decryptedPlaintext = decrypt(ciphertext);

    // display decrypted plaintext
    System.out.println("Decrypted plaintext = " + decryptedPlaintext);
    }
}