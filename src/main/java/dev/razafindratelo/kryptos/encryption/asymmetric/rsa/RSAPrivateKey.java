package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import java.math.BigInteger;

public record RSAPrivateKey(BigInteger n, BigInteger d) {

  public RSAPrivateKey {
    if (n == null) throw new IllegalArgumentException("n must not be null");
    if (d == null) throw new IllegalArgumentException("d must not be null");
  }
}
