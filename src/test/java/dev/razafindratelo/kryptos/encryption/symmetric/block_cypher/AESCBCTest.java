package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class AESCBCTest {

  private byte[] randomBlock() {
    return SecureRandom.getSeed(16);
  }

  private byte[] randomKey(AESVariant variant) {
    return SecureRandom.getSeed(variant.getKeyBytes());
  }

  private byte[] randomIV() {
    return SecureRandom.getSeed(16);
  }

  private byte[] jdkEncryptCBC(byte[] block, byte[] key, byte[] iv) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return cipher.doFinal(block);
  }

  @Test
  void should_throw_on_null_block() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class,
        () -> cbc.encrypt(null, randomKey(AESVariant.AES_128), randomIV()));
  }

  @Test
  void should_throw_on_null_key() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class, () -> cbc.encrypt(randomBlock(), null, randomIV()));
  }

  @Test
  void should_throw_on_null_iv() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class,
        () -> cbc.encrypt(randomBlock(), randomKey(AESVariant.AES_128), null));
  }

  @Test
  void should_throw_on_wrong_block_size() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class,
        () -> cbc.encrypt(SecureRandom.getSeed(15), randomKey(AESVariant.AES_128), randomIV()));
  }

  @Test
  void should_throw_on_wrong_iv_size() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class,
        () -> cbc.encrypt(randomBlock(), randomKey(AESVariant.AES_128), SecureRandom.getSeed(8)));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_throw_on_wrong_key_size(AESVariant variant) {
    AESCBC cbc = AESCBC.of(variant);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            cbc.encrypt(
                randomBlock(), SecureRandom.getSeed(variant.getKeyBytes() - 1), randomIV()));
  }

  @Test
  void should_produce_identical_ciphertext_on_identical_blocks_with_ecb() {
    // OWASP A02:2021 -- Cryptographic Failures: ECB mode leaks block patterns
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] c1 = AES.of(AESVariant.AES_128).encrypt(block, key);
    byte[] c2 = AES.of(AESVariant.AES_128).encrypt(block, key);
    assertArrayEquals(c1, c2);
  }

  @Test
  void should_produce_different_ciphertext_on_identical_blocks_with_cbc() {
    // CBC XORs each block with previous ciphertext -- identical plaintext blocks
    // produce different ciphertext blocks, defeating pattern analysis
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv1 = randomIV();
    byte[] iv2 = randomIV();
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertFalse(Arrays.equals(cbc.encrypt(block, key, iv1), cbc.encrypt(block, key, iv2)));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_decrypt_to_original_on_encrypt_then_decrypt(AESVariant variant) {
    AESCBC cbc = AESCBC.of(variant);
    byte[] block = randomBlock();
    byte[] key = randomKey(variant);
    byte[] iv = randomIV();
    byte[] encrypted = cbc.encrypt(block, key, iv);
    byte[] actual = cbc.decrypt(encrypted, key, iv);
    assertArrayEquals(block, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes128_encrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    byte[] actual = AESCBC.of(AESVariant.AES_128).encrypt(block, key, iv);
    byte[] expected = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes192_encrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] iv = randomIV();
    byte[] actual = AESCBC.of(AESVariant.AES_192).encrypt(block, key, iv);
    byte[] expected = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes256_encrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] iv = randomIV();
    byte[] actual = AESCBC.of(AESVariant.AES_256).encrypt(block, key, iv);
    byte[] expected = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes128_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    byte[] encrypted = jdkEncryptCBC(block, key, iv);
    byte[] actual = AESCBC.of(AESVariant.AES_128).decrypt(encrypted, key, iv);
    assertArrayEquals(block, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes192_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] iv = randomIV();
    byte[] encrypted = jdkEncryptCBC(block, key, iv);
    byte[] actual = AESCBC.of(AESVariant.AES_192).decrypt(encrypted, key, iv);
    assertArrayEquals(block, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_cbc_aes256_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] iv = randomIV();
    byte[] encrypted = jdkEncryptCBC(block, key, iv);
    byte[] actual = AESCBC.of(AESVariant.AES_256).decrypt(encrypted, key, iv);
    assertArrayEquals(block, actual);
  }

  @Test
  void should_demonstrate_bit_flipping_attack_on_cbc() {
    // RFC 4107 -- without authentication, CBC ciphertext is malleable.
    // Flipping bit i in ciphertext block n garbles block n and
    // predictably flips bit i in block n+1 plaintext.
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    byte[] cipher = cbc.encrypt(block, key, iv);
    cipher[0] ^= (byte) 0xFF;
    byte[] tampered = cbc.decrypt(cipher, key, iv);
    assertFalse(Arrays.equals(block, tampered));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_variant() {
    assertThrows(IllegalArgumentException.class, () -> AESCBC.of(null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_block_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC.of(AESVariant.AES_128).encrypt(null, randomKey(AESVariant.AES_128), randomIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AESCBC.of(AESVariant.AES_128).encrypt(randomBlock(), null, randomIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_iv_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC
                .of(AESVariant.AES_128)
                .encrypt(randomBlock(), randomKey(AESVariant.AES_128), null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_wrong_block_size_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC
                .of(AESVariant.AES_128)
                .encrypt(SecureRandom.getSeed(15), randomKey(AESVariant.AES_128), randomIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_wrong_iv_size_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC
                .of(AESVariant.AES_128)
                .encrypt(randomBlock(), randomKey(AESVariant.AES_128), SecureRandom.getSeed(8)));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_throw_illegal_argument_exception_on_wrong_key_size_encrypt(AESVariant variant) {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC
                .of(variant)
                .encrypt(
                    randomBlock(), SecureRandom.getSeed(variant.getKeyBytes() - 1), randomIV()));
  }

  // -------------------------------------------------------------------------
  // input validation -- decrypt
  // -------------------------------------------------------------------------

  @Test
  void should_throw_illegal_argument_exception_on_null_block_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC.of(AESVariant.AES_128).decrypt(null, randomKey(AESVariant.AES_128), randomIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AESCBC.of(AESVariant.AES_128).decrypt(randomBlock(), null, randomIV()));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_iv_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AESCBC
                .of(AESVariant.AES_128)
                .decrypt(randomBlock(), randomKey(AESVariant.AES_128), null));
  }

  // -------------------------------------------------------------------------
  // xor
  // -------------------------------------------------------------------------

  @Test
  void should_return_zero_array_on_xor_with_itself() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    byte[] block = randomBlock();
    byte[] actual = cbc.xor(block, block);
    assertArrayEquals(new byte[16], actual);
  }

  @Test
  void should_recover_original_on_double_xor() {
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    byte[] block = randomBlock();
    byte[] key = randomBlock();
    byte[] actual = cbc.xor(cbc.xor(block, key), key);
    assertArrayEquals(block, actual);
  }

  // -------------------------------------------------------------------------
  // ECB weakness vs CBC -- OWASP A02:2021 Cryptographic Failures
  // -------------------------------------------------------------------------

  @Test
  void should_produce_identical_ciphertext_on_identical_plaintext_blocks_with_ecb() {
    // OWASP A02:2021: ECB mode leaks plaintext patterns through ciphertext structure
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    assertArrayEquals(
        AES.of(AESVariant.AES_128).encrypt(block, key),
        AES.of(AESVariant.AES_128).encrypt(block, key));
  }

  @Test
  void should_produce_different_ciphertext_on_identical_plaintext_blocks_with_different_ivs() {
    // OWASP A02:2021: CBC IV chaining breaks ciphertext determinism
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    assertFalse(
        Arrays.equals(cbc.encrypt(block, key, randomIV()), cbc.encrypt(block, key, randomIV())));
  }

  // -------------------------------------------------------------------------
  // correctness -- encrypt then decrypt
  // -------------------------------------------------------------------------

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_recover_plaintext_on_encrypt_then_decrypt(AESVariant variant) {
    AESCBC cbc = AESCBC.of(variant);
    byte[] block = randomBlock();
    byte[] key = randomKey(variant);
    byte[] iv = randomIV();
    assertArrayEquals(block, cbc.decrypt(cbc.encrypt(block, key, iv), key, iv));
  }

  // -------------------------------------------------------------------------
  // correctness -- against JDK (encrypt)
  // -------------------------------------------------------------------------

  @RepeatedTest(10)
  void should_match_jdk_on_aes128_cbc_encrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    assertArrayEquals(
        jdkEncryptCBC(block, key, iv), AESCBC.of(AESVariant.AES_128).encrypt(block, key, iv));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_aes192_cbc_encrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] iv = randomIV();
    assertArrayEquals(
        jdkEncryptCBC(block, key, iv), AESCBC.of(AESVariant.AES_192).encrypt(block, key, iv));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_aes256_cbc_encrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] iv = randomIV();
    assertArrayEquals(
        jdkEncryptCBC(block, key, iv), AESCBC.of(AESVariant.AES_256).encrypt(block, key, iv));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_aes128_cbc_decrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    byte[] cipher = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(block, AESCBC.of(AESVariant.AES_128).decrypt(cipher, key, iv));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_aes192_cbc_decrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] iv = randomIV();
    byte[] cipher = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(block, AESCBC.of(AESVariant.AES_192).decrypt(cipher, key, iv));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_aes256_cbc_decrypt() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] iv = randomIV();
    byte[] cipher = jdkEncryptCBC(block, key, iv);
    assertArrayEquals(block, AESCBC.of(AESVariant.AES_256).decrypt(cipher, key, iv));
  }

  @Test
  void should_corrupt_plaintext_on_ciphertext_bit_flip() {
    // RFC 4107: CBC without authentication is malleable. Flipping bits in
    // ciphertext block n predictably corrupts plaintext block n+1.
    AESCBC cbc = AESCBC.of(AESVariant.AES_128);
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] iv = randomIV();
    byte[] cipher = cbc.encrypt(block, key, iv);
    cipher[0] ^= (byte) 0xFF;
    assertFalse(Arrays.equals(block, cbc.decrypt(cipher, key, iv)));
  }
}
