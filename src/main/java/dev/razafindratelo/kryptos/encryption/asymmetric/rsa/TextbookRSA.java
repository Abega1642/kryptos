package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import java.math.BigInteger;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TextbookRSA {

  private static final TextbookRSA INSTANCE = new TextbookRSA();

  public static TextbookRSA getInstance() {
    return INSTANCE;
  }

  public BigInteger encrypt(BigInteger message, RSAPublicKey publicKey) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");

    if (publicKey == null) throw new IllegalArgumentException("Public key must not be null");

    if (message.compareTo(publicKey.n()) >= 0)
      throw new IllegalArgumentException("Message must be less than n");
    if (message.signum() < 0) throw new IllegalArgumentException("Message must be non-negative");

    return message.modPow(publicKey.e(), publicKey.n());
  }

  public BigInteger decrypt(BigInteger ciphertext, RSAPrivateKey privateKey) {
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");

    if (privateKey == null) throw new IllegalArgumentException("Private key must not be null");

    if (ciphertext.signum() < 0)
      throw new IllegalArgumentException("Ciphertext must be non-negative");

    return ciphertext.modPow(privateKey.d(), privateKey.n());
  }

  public BigInteger sign(BigInteger message, RSAPrivateKey privateKey) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");

    if (privateKey == null) throw new IllegalArgumentException("Private key must not be null");

    if (message.compareTo(privateKey.n()) >= 0)
      throw new IllegalArgumentException("Message must be less than n");

    return message.modPow(privateKey.d(), privateKey.n());
  }

  public boolean verify(BigInteger message, BigInteger signature, RSAPublicKey publicKey) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");

    if (signature == null) throw new IllegalArgumentException("Signature must not be null");

    if (publicKey == null) throw new IllegalArgumentException("Public key must not be null");

    return message.equals(signature.modPow(publicKey.e(), publicKey.n()));
  }
}
