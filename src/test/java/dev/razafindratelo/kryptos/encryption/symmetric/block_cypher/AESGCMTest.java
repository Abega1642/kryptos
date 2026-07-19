package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class AESGCMTest {

  public static final int MAX = 0xFF;

  private byte[] randomKey(AESVariant variant) {
    return SecureRandom.getSeed(variant.getKeyBytes());
  }

  private byte[] randomPlaintext() {
    return SecureRandom.getSeed(64);
  }

  private byte[] randomAAD() {
    return SecureRandom.getSeed(32);
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_variant() {
    assertThrows(IllegalArgumentException.class, () -> AESGCM.of(null));
  }

  @Test
  void should_produce_12_bytes_on_generate_iv() {
    assertEquals(12, AESGCM.of(AESVariant.AES_128).generateIV().length);
  }

  @RepeatedTest(10)
  void should_produce_unique_iv_on_each_call() {
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    assertFalse(Arrays.equals(aesgcm.generateIV(), aesgcm.generateIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_plaintext() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AESGCM.of(AESVariant.AES_128).encrypt(null, randomKey(AESVariant.AES_128), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AESGCM.of(AESVariant.AES_128).encrypt(randomPlaintext(), null, null));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_throw_illegal_argument_exception_on_wrong_key_size_encrypt(AESVariant variant) {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESGCM
                .of(variant)
                .encrypt(randomPlaintext(), SecureRandom.getSeed(variant.getKeyBytes() - 1), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_ciphertext() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AESGCM.of(AESVariant.AES_128).decrypt(null, randomKey(AESVariant.AES_128), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_decrypt() {
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, null);
    assertThrows(IllegalArgumentException.class, () -> aesgcm.decrypt(ct, null, null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_iv_in_ciphertext() {
    assertThrows(IllegalArgumentException.class, () -> new AESGCMCiphertext(null, new byte[16]));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_ciphertext_in_record() {
    assertThrows(IllegalArgumentException.class, () -> new AESGCMCiphertext(new byte[12], null));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_recover_plaintext_on_encrypt_then_decrypt_without_aad(AESVariant variant) {
    AESGCM aesgcm = AESGCM.of(variant);
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(variant);
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, null);
    byte[] actual = aesgcm.decrypt(ct, key, null);
    assertArrayEquals(plaintext, actual);
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_recover_plaintext_on_encrypt_then_decrypt_with_aad(AESVariant variant) {
    AESGCM aesgcm = AESGCM.of(variant);
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(variant);
    byte[] aad = randomAAD();
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, aad);
    byte[] actual = aesgcm.decrypt(ct, key, aad);
    assertArrayEquals(plaintext, actual);
  }

  @Test
  void should_throw_on_tampered_ciphertext() {
    // NIST SP 800-38D: authentication tag verification must fail on any modification
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, null);
    byte[] tampered = ct.ciphertext().clone();
    tampered[0] ^= (byte) MAX;
    assertThrows(
        IllegalStateException.class,
        () -> aesgcm.decrypt(new AESGCMCiphertext(ct.iv(), tampered), key, null));
  }

  @Test
  void should_throw_on_tampered_iv() {
    // NIST SP 800-38D: IV modification breaks counter derivation, tag fails
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, null);
    byte[] tamperedIV = ct.iv().clone();
    tamperedIV[0] ^= (byte) MAX;
    assertThrows(
        IllegalStateException.class,
        () -> aesgcm.decrypt(new AESGCMCiphertext(tamperedIV, ct.ciphertext()), key, null));
  }

  @Test
  void should_throw_on_tampered_aad() {
    // NIST SP 800-38D: AAD is authenticated but not encrypted -- any change invalidates tag
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] aad = randomAAD();
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, aad);
    byte[] tamperedAAD = aad.clone();
    tamperedAAD[0] ^= (byte) MAX;
    assertThrows(IllegalStateException.class, () -> aesgcm.decrypt(ct, key, tamperedAAD));
  }

  @Test
  void should_throw_on_wrong_key_decrypt() {
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, null);
    assertThrows(
        IllegalStateException.class, () -> aesgcm.decrypt(ct, randomKey(AESVariant.AES_128), null));
  }

  @Test
  void should_reject_bit_flipped_ciphertext_unlike_cbc() {
    // RFC 5116: AEAD schemes must reject any modified ciphertext.
    // CBC silently decrypts tampered ciphertext. GCM rejects it.
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(randomPlaintext(), key, null);
    byte[] tampered = ct.ciphertext().clone();
    tampered[0] ^= (byte) MAX;
    assertThrows(
        IllegalStateException.class,
        () -> aesgcm.decrypt(new AESGCMCiphertext(ct.iv(), tampered), key, null));
  }

  @RepeatedTest(10)
  void should_produce_different_ciphertext_on_same_plaintext_and_key() {
    // NIST SP 800-38D: IV must never be reused with the same key.
    // Each encrypt call generates a fresh IV, so ciphertext differs.
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_128);
    assertFalse(
        Arrays.equals(
            aesgcm.encrypt(plaintext, key, null).ciphertext(),
            aesgcm.encrypt(plaintext, key, null).ciphertext()));
  }

  @Test
  void should_encrypt_and_decrypt_empty_plaintext() {
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(new byte[0], key, null);
    byte[] actual = aesgcm.decrypt(ct, key, null);
    assertArrayEquals(new byte[0], actual);
  }

  @Test
  void should_authenticate_aad_only_on_empty_plaintext() {
    // GCM can authenticate metadata alone with no payload -- used in network protocols
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] aad = randomAAD();
    AESGCMCiphertext ct = aesgcm.encrypt(new byte[0], key, aad);
    byte[] actual = aesgcm.decrypt(ct, key, aad);
    assertArrayEquals(new byte[0], actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_aes128_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] iv = aesgcm.generateIV();
    byte[] jdkCipher = jdkEncryptGCM(plaintext, key, iv, null);
    byte[] actual = aesgcm.decrypt(new AESGCMCiphertext(iv, jdkCipher), key, null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_aes192_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_192);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_192);
    byte[] iv = aesgcm.generateIV();
    byte[] jdkCipher = jdkEncryptGCM(plaintext, key, iv, null);
    byte[] actual = aesgcm.decrypt(new AESGCMCiphertext(iv, jdkCipher), key, null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_aes256_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_256);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_256);
    byte[] iv = aesgcm.generateIV();
    byte[] jdkCipher = jdkEncryptGCM(plaintext, key, iv, null);
    byte[] actual = aesgcm.decrypt(new AESGCMCiphertext(iv, jdkCipher), key, null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_aes128_with_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] aad = randomAAD();
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    byte[] iv = aesgcm.generateIV();
    byte[] jdkCipher = jdkEncryptGCM(plaintext, key, iv, aad);
    byte[] actual = aesgcm.decrypt(new AESGCMCiphertext(iv, jdkCipher), key, aad);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_aes128_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_128);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, null);
    byte[] actual = jdkDecryptGCM(ct.ciphertext(), key, ct.iv(), null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_aes192_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_192);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_192);
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, null);
    byte[] actual = jdkDecryptGCM(ct.ciphertext(), key, ct.iv(), null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_aes256_without_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_256);
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_256);
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, null);
    byte[] actual = jdkDecryptGCM(ct.ciphertext(), key, ct.iv(), null);
    assertArrayEquals(plaintext, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_aes128_with_aad() throws Exception {
    byte[] plaintext = randomPlaintext();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] aad = randomAAD();
    AESGCM aesgcm = AESGCM.of(AESVariant.AES_128);
    AESGCMCiphertext ct = aesgcm.encrypt(plaintext, key, aad);
    byte[] actual = jdkDecryptGCM(ct.ciphertext(), key, ct.iv(), aad);
    assertArrayEquals(plaintext, actual);
  }

  private byte[] jdkEncryptGCM(byte[] plaintext, byte[] key, byte[] iv, byte[] aad)
      throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    if (aad != null) cipher.updateAAD(aad);

    return cipher.doFinal(plaintext);
  }

  private byte[] jdkDecryptGCM(byte[] ciphertext, byte[] key, byte[] iv, byte[] aad)
      throws Exception {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    if (aad != null) cipher.updateAAD(aad);

    return cipher.doFinal(ciphertext);
  }
}
