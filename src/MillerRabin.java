package crypto;
import java.math.BigInteger;

public class MillerRabin {
    /**
     * Miller-Rabin primality test.
     * check if n is prime or not.
        1- Chose k,q such that n-1 = 2^k*q where q is odd number and k >= 1
        2- Chose a random number a such th   1 < a < n-1
        3- Compute if a^q mod n = 1 then it's maybe prime
        4- for i = 0 to k-1 if a^(2^i * q) mod n = n-1 then it's maybe prime
        5- if none of the above conditions are satisfied then it's composite
     */
    public static boolean MillerRabinTest(BigInteger n) {
        // if n is even then it's not prime
        if (n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            return false;
        }

        // find q and k such that n-1 = 2^k * q
        BigInteger q = n.subtract(BigInteger.ONE);
        int k = 0;
        while (q.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            q = q.divide(BigInteger.valueOf(2));
            k++;
        }

        // choose a random number a such that 1 < a < n-1
        BigInteger a = BigInteger.valueOf(2);
        for (int i = 0; i < k; i++) {
            // if a^q mod n = 1 then it's maybe prime
            if (a.modPow(q, n).equals(BigInteger.ONE)) {
                return true;
            }
            // if a^(2^i * q) mod n = n-1 then it's maybe prime
            if (a.modPow(BigInteger.valueOf(2).pow(i).multiply(q), n).equals(n.subtract(BigInteger.ONE))) {
                return true;
            }
        }
        // if none of the above conditions are satisfied then it's composite
        return false;
    }

    public static void main(String[] args) {
        // test the Miller-Rabin primality test with some big prime numbers
        BigInteger n = new BigInteger("29");

        if (MillerRabinTest(n)) {
            System.out.println(n + " is prime");
        } else {
            System.out.println(n + " is composite");
        }

        // n = new BigInteger("100004");

        // if (MillerRabinTest(n)) {
        //     System.out.println(n + " is prime");
        // } else {
        //     System.out.println(n + " is composite");
        // }

        // n = new BigInteger("100019");

        // if (MillerRabinTest(n)) {
        //     System.out.println(n + " is prime");
        // } else {
        //     System.out.println(n + " is composite");
        // }

        // n = new BigInteger("100043");

        // if (MillerRabinTest(n)) {
        //     System.out.println(n + " is prime");
        // } else {
        //     System.out.println(n + " is composite");
        // }
    }

}