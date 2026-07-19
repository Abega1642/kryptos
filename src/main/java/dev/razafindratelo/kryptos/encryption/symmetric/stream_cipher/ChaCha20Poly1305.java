package dev.razafindratelo.kryptos.encryption.symmetric.stream_cipher;

import static java.lang.String.format;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class ChaCha20Poly1305 {

  private static final int KEY_SIZE_BYTES = 32;
  private static final int NONCE_SIZE_BYTES = 12;
  private static final String ALGORITHM = "ChaCha20-Poly1305";

  private final SecureRandom secureRandom;

  public static ChaCha20Poly1305 getInstance() {
    return new ChaCha20Poly1305(new SecureRandom());
  }

  public byte[] generateNonce() {
    byte[] nonce = new byte[NONCE_SIZE_BYTES];

    secureRandom.nextBytes(nonce);

    return nonce;
  }

  public ChaCha20Ciphertext encrypt(byte[] plaintext, byte[] key, byte[] aad) {
    validateEncryptInput(plaintext, key);
    try {
      byte[] nonce = generateNonce();
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      cipher.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));

      if (aad != null) cipher.updateAAD(aad);

      byte[] ciphertext = cipher.doFinal(plaintext);

      return new ChaCha20Ciphertext(nonce, ciphertext);
    } catch (Exception e) {
      throw new IllegalStateException("ChaCha20-Poly1305 encryption failed", e);
    }
  }

  public byte[] decrypt(ChaCha20Ciphertext ciphertext, byte[] key, byte[] aad) {
    validateDecryptInput(ciphertext, key);
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "ChaCha20"),
          new IvParameterSpec(ciphertext.nonce()));

      if (aad != null) cipher.updateAAD(aad);

      return cipher.doFinal(ciphertext.ciphertext());

    } catch (Exception e) {
      throw new IllegalStateException(
          "ChaCha20-Poly1305 decryption failed: authentication tag mismatch", e);
    }
  }

  private void validateEncryptInput(byte[] plaintext, byte[] key) {
    if (plaintext == null) throw new IllegalArgumentException("Plaintext must not be null");

    if (key == null) throw new IllegalArgumentException("Key must not be null");

    if (key.length != KEY_SIZE_BYTES)
      throw new IllegalArgumentException(
          format("Key must be %d bytes, got %d", KEY_SIZE_BYTES, key.length));
  }

  private void validateDecryptInput(ChaCha20Ciphertext ciphertext, byte[] key) {
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");

    if (key == null) throw new IllegalArgumentException("Key must not be null");

    if (ciphertext.nonce() == null) throw new IllegalArgumentException("Nonce must not be null");

    if (ciphertext.nonce().length != NONCE_SIZE_BYTES)
      throw new IllegalArgumentException(
          format("Nonce must be %d bytes, got %d", NONCE_SIZE_BYTES, ciphertext.nonce().length));

    if (key.length != KEY_SIZE_BYTES)
      throw new IllegalArgumentException(
          format("Key must be %d bytes, got %d", KEY_SIZE_BYTES, key.length));
  }
}
