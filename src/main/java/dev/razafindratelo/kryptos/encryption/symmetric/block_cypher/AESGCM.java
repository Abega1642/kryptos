package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static java.lang.String.format;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class AESGCM {

  private static final int IV_SIZE_BYTES = 12;
  private static final int TAG_SIZE_BITS = 128;
  private static final String ALGORITHM = "AES/GCM/NoPadding";

  private final AESVariant variant;
  private final SecureRandom secureRandom;

  public static AESGCM of(AESVariant variant) {
    if (variant == null) throw new IllegalArgumentException("Variant must not be null");

    return new AESGCM(variant, new SecureRandom());
  }

  public byte[] generateIV() {
    byte[] iv = new byte[IV_SIZE_BYTES];
    secureRandom.nextBytes(iv);

    return iv;
  }

  public AESGCMCiphertext encrypt(byte[] plaintext, byte[] key, byte[] aad) {
    validateEncryptInput(plaintext, key);
    try {
      byte[] iv = generateIV();
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      SecretKey sk = new SecretKeySpec(key, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(TAG_SIZE_BITS, iv));

      if (aad != null) cipher.updateAAD(aad);

      byte[] ciphertext = cipher.doFinal(plaintext);

      return new AESGCMCiphertext(iv, ciphertext);
    } catch (Exception e) {
      throw new IllegalStateException("AES-GCM encryption failed", e);
    }
  }

  public byte[] decrypt(AESGCMCiphertext ciphertext, byte[] key, byte[] aad) {
    validateDecryptInput(ciphertext, key);
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      SecretKey sk = new SecretKeySpec(key, "AES");
      cipher.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(TAG_SIZE_BITS, ciphertext.iv()));

      if (aad != null) cipher.updateAAD(aad);

      return cipher.doFinal(ciphertext.ciphertext());
    } catch (Exception e) {
      throw new IllegalStateException("AES-GCM decryption failed: authentication tag mismatch", e);
    }
  }

  private void validateEncryptInput(byte[] plaintext, byte[] key) {
    if (plaintext == null) throw new IllegalArgumentException("Plaintext must not be null");

    if (key == null) throw new IllegalArgumentException("Key must not be null");

    if (key.length != variant.getKeyBytes())
      throw new IllegalArgumentException(
          format(
              "Key must be %d bytes for %s, got %d", variant.getKeyBytes(), variant, key.length));
  }

  private void validateDecryptInput(AESGCMCiphertext ciphertext, byte[] key) {
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");

    if (key == null) throw new IllegalArgumentException("Key must not be null");

    if (ciphertext.iv() == null) throw new IllegalArgumentException("IV must not be null");

    if (ciphertext.iv().length != IV_SIZE_BYTES)
      throw new IllegalArgumentException(
          format("IV must be %d bytes, got %d", IV_SIZE_BYTES, ciphertext.iv().length));

    if (key.length != variant.getKeyBytes())
      throw new IllegalArgumentException(
          format(
              "Key must be %d bytes for %s, got %d", variant.getKeyBytes(), variant, key.length));
  }
}
