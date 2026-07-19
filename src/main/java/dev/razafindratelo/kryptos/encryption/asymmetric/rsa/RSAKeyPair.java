package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

public record RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
  public RSAKeyPair {
    if (publicKey == null) throw new IllegalArgumentException("Public key must not be null");
    if (privateKey == null) throw new IllegalArgumentException("Private key must not be null");
  }
}
