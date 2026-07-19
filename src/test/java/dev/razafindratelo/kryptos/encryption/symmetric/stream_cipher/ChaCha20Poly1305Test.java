package dev.razafindratelo.kryptos.encryption.symmetric.stream_cipher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class ChaCha20Poly1305Test {

  private byte[] randomKey() {
    return SecureRandom.getSeed(32);
  }

  private byte[] randomPlaintext() {
    return SecureRandom.getSeed(64);
  }

  private byte[] randomAAD() {
    return SecureRandom.getSeed(32);
  }

  private byte[] jdkEncrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[] aad)
      throws Exception {
    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
    cipher.init(
        Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
    if (aad != null) cipher.updateAAD(aad);

    return cipher.doFinal(plaintext);
  }

  private byte[] jdkDecrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[] aad)
      throws Exception {
    Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
    cipher.init(
        Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
    if (aad != null) cipher.updateAAD(aad);

    return cipher.doFinal(ciphertext);
  }

  @Test
  void should_produce_12_bytes_on_generate_nonce() {
    assertEquals(12, ChaCha20Poly1305.getInstance().generateNonce().length);
  }

  @RepeatedTest(10)
  void should_produce_unique_nonce_on_each_call() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    assertFalse(Arrays.equals(chacha.generateNonce(), chacha.generateNonce()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_plaintext() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ChaCha20Poly1305.getInstance().encrypt(null, randomKey(), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ChaCha20Poly1305.getInstance().encrypt(randomPlaintext(), null, null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_wrong_key_size_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ChaCha20Poly1305.getInstance()
                .encrypt(randomPlaintext(), SecureRandom.getSeed(16), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_ciphertext_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ChaCha20Poly1305.getInstance().decrypt(null, randomKey(), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_decrypt() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), randomKey(), null);
    assertThrows(IllegalArgumentException.class, () -> chacha.decrypt(ct, null, null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_wrong_key_size_decrypt() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), randomKey(), null);
    assertThrows(
        IllegalArgumentException.class, () -> chacha.decrypt(ct, SecureRandom.getSeed(16), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_nonce_in_record() {
    assertThrows(IllegalArgumentException.class, () -> new ChaCha20Ciphertext(null, new byte[16]));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_ciphertext_in_record() {
    assertThrows(IllegalArgumentException.class, () -> new ChaCha20Ciphertext(new byte[12], null));
  }

  @Test
  void should_recover_plaintext_on_encrypt_then_decrypt_without_aad() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    ChaCha20Ciphertext ct = chacha.encrypt(plaintext, key, null);
    assertArrayEquals(plaintext, chacha.decrypt(ct, key, null));
  }

  @Test
  void should_recover_plaintext_on_encrypt_then_decrypt_with_aad() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    byte[] aad = randomAAD();
    ChaCha20Ciphertext ct = chacha.encrypt(plaintext, key, aad);
    assertArrayEquals(plaintext, chacha.decrypt(ct, key, aad));
  }

  @Test
  void should_encrypt_and_decrypt_empty_plaintext() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] key = randomKey();
    ChaCha20Ciphertext ct = chacha.encrypt(new byte[0], key, null);
    assertArrayEquals(new byte[0], chacha.decrypt(ct, key, null));
  }

  @Test
  void should_throw_on_tampered_ciphertext() {
    // RFC 8439: Poly1305 tag verification must fail on any ciphertext modification
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] key = randomKey();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), key, null);
    byte[] tampered = ct.ciphertext().clone();
    tampered[0] ^= (byte) 0xFF;
    assertThrows(
        IllegalStateException.class,
        () -> chacha.decrypt(new ChaCha20Ciphertext(ct.nonce(), tampered), key, null));
  }

  @Test
  void should_throw_on_tampered_nonce() {
    // RFC 8439: nonce modification breaks keystream derivation, tag fails
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] key = randomKey();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), key, null);
    byte[] tamperedNonce = ct.nonce().clone();
    tamperedNonce[0] ^= (byte) 0xFF;
    assertThrows(
        IllegalStateException.class,
        () -> chacha.decrypt(new ChaCha20Ciphertext(tamperedNonce, ct.ciphertext()), key, null));
  }

  @Test
  void should_throw_on_tampered_aad() {
    // RFC 8439: AAD is authenticated but not encrypted
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] key = randomKey();
    byte[] aad = randomAAD();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), key, aad);
    byte[] tamperedAAD = aad.clone();
    tamperedAAD[0] ^= (byte) 0xFF;
    assertThrows(IllegalStateException.class, () -> chacha.decrypt(ct, key, tamperedAAD));
  }

  @Test
  void should_throw_on_wrong_key_decrypt() {
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    ChaCha20Ciphertext ct = chacha.encrypt(randomPlaintext(), randomKey(), null);
    assertThrows(IllegalStateException.class, () -> chacha.decrypt(ct, randomKey(), null));
  }

  @RepeatedTest(10)
  void should_produce_different_ciphertext_on_same_plaintext_and_key() {
    // RFC 8439: nonce must never be reused with the same key
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    assertFalse(
        Arrays.equals(
            chacha.encrypt(plaintext, key, null).ciphertext(),
            chacha.encrypt(plaintext, key, null).ciphertext()));
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] nonce = chacha.generateNonce();
    byte[] jdkCipher = jdkEncrypt(plaintext, key, nonce, null);
    byte[] actual = chacha.decrypt(new ChaCha20Ciphertext(nonce, jdkCipher), key, null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_with_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    byte[] aad = randomAAD();
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    byte[] nonce = chacha.generateNonce();
    byte[] jdkCipher = jdkEncrypt(plaintext, key, nonce, aad);
    byte[] actual = chacha.decrypt(new ChaCha20Ciphertext(nonce, jdkCipher), key, aad);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    ChaCha20Ciphertext ct = chacha.encrypt(plaintext, key, null);
    byte[] actual = jdkDecrypt(ct.ciphertext(), key, ct.nonce(), null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_with_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey();
    byte[] aad = randomAAD();
    ChaCha20Poly1305 chacha = ChaCha20Poly1305.getInstance();
    ChaCha20Ciphertext ct = chacha.encrypt(plaintext, key, aad);
    byte[] actual = jdkDecrypt(ct.ciphertext(), key, ct.nonce(), aad);
    assertArrayEquals(plaintext, actual);
  }
}
