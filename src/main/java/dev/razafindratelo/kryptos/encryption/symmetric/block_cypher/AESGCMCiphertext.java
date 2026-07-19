package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

public record AESGCMCiphertext(byte[] iv, byte[] ciphertext) {

  public AESGCMCiphertext {
    if (iv == null) throw new IllegalArgumentException("IV must not be null");
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");
  }
}
