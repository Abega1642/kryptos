package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import java.math.BigInteger;
import java.security.SecureRandom;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RSAKeyGenerator {

  private static final BigInteger E = BigInteger.valueOf(65_537);
  private static final int PRIMALITY_CERTAINTY = 100;
  private static final RSAKeyGenerator INSTANCE = new RSAKeyGenerator();

  public static RSAKeyGenerator getInstance() {
    return INSTANCE;
  }

  public BigInteger generatePrime(int bitLength, SecureRandom random) {
    BigInteger prime;
    do {
      prime = new BigInteger(bitLength, random);
    } while (!prime.isProbablePrime(PRIMALITY_CERTAINTY) || !isValidPrime(prime));
    return prime;
  }

  public boolean isValidPrime(BigInteger candidate) {
    // e and (p-1) must be coprime: gcd(e, p-1) = 1
    return candidate.subtract(BigInteger.ONE).gcd(E).equals(BigInteger.ONE);
  }

  public RSAKeyPair generate(int bitLength) {
    if (bitLength < 512)
      throw new IllegalArgumentException(
          String.format("Bit length must be at least 512, got %d", bitLength));

    SecureRandom random = new SecureRandom();
    int halfBits = bitLength / 2;

    BigInteger p, q, n, phi;

    do {
      p = generatePrime(halfBits, random);
      q = generatePrime(halfBits, random);
      n = p.multiply(q);
      phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    } while (p.equals(q) || !E.gcd(phi).equals(BigInteger.ONE));

    BigInteger d = E.modInverse(phi);

    return new RSAKeyPair(new RSAPublicKey(n, E), new RSAPrivateKey(n, d));
  }
}
