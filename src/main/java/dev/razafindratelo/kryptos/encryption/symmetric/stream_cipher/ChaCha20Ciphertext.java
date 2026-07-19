package dev.razafindratelo.kryptos.encryption.symmetric.stream_cipher;

public record ChaCha20Ciphertext(byte[] nonce, byte[] ciphertext) {

  public ChaCha20Ciphertext {
    if (nonce == null) throw new IllegalArgumentException("Nonce must not be null");
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");
  }
}
