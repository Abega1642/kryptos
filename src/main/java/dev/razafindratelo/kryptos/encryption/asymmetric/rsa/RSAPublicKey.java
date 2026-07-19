package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import java.math.BigInteger;

public record RSAPublicKey(BigInteger n, BigInteger e) {

  public RSAPublicKey {
    if (n == null) throw new IllegalArgumentException("n must not be null");
    if (e == null) throw new IllegalArgumentException("e must not be null");
  }
}
