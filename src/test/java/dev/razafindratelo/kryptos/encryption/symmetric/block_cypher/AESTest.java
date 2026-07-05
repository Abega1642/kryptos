package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class AESTest {

  private byte[] jdkEncrypt(byte[] block, byte[] key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

    return cipher.doFinal(block);
  }

  private byte[] randomBlock() {
    return SecureRandom.getSeed(16);
  }

  private byte[] randomKey(AESVariant variant) {
    return SecureRandom.getSeed(variant.getKeyBytes());
  }

  @Test
  void should_throw_on_null_variant() {
    assertThrows(IllegalArgumentException.class, () -> AES.of(null));
  }

  @Test
  void should_recover_original_block_on_toState_then_fromState() {
    byte[] block = randomBlock();
    AES aes = AES.of(AESVariant.AES_128);
    byte[] actual = aes.fromState(aes.toState(block));
    assertArrayEquals(block, actual);
  }

  @Test
  void should_fill_state_column_by_column_on_toState() {
    // FIPS 197 section 3.4: bytes fill column by column
    byte[] block = new byte[16];
    for (int i = 0; i < 16; i++) block[i] = (byte) i;
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(block);
    assertEquals((byte) 0x00, state[0][0]);
    assertEquals((byte) 0x01, state[1][0]);
    assertEquals((byte) 0x02, state[2][0]);
    assertEquals((byte) 0x03, state[3][0]);
    assertEquals((byte) 0x04, state[0][1]);
  }

  @Test
  void should_produce_correct_xtime_on_no_overflow() {
    // xtime(0x01) = 0x02
    assertEquals(0x02, AES.of(AESVariant.AES_128).xtime(0x01));
  }

  @Test
  void should_reduce_with_0x1b_on_overflow() {
    // xtime(0x80) = 0x1b (high bit set, reduction applied)
    assertEquals(0x1b, AES.of(AESVariant.AES_128).xtime(0x80));
  }

  @Test
  void should_produce_correct_gfMultiply_on_known_values() {
    AES aes = AES.of(AESVariant.AES_128);
    // FIPS 197 section 4.2.1: {02} * {87} = {15}
    assertEquals(0x15, aes.gfMultiply(0x02, 0x87));
    // {03} * {6e} = {b2}
    assertEquals(0xb2, aes.gfMultiply(0x03, 0x6e));
  }

  @Test
  void should_recover_state_on_subBytes_then_invSubBytes() {
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(randomBlock());
    byte[][] actual = aes.invSubBytes(aes.subBytes(state));
    assertArrayEquals(state, actual);
  }

  @Test
  void should_substitute_known_byte_on_subBytes() {
    // FIPS 197: S_BOX[0x00] = 0x63
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = new byte[4][4];
    byte[][] actual = aes.subBytes(state);
    assertEquals((byte) 0x63, actual[0][0]);
  }

  @Test
  void should_recover_state_on_shiftRows_then_invShiftRows() {
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(randomBlock());
    byte[][] actual = aes.invShiftRows(aes.shiftRows(state));
    assertArrayEquals(state, actual);
  }

  @Test
  void should_not_shift_first_row_on_shiftRows() {
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(randomBlock());
    byte[][] actual = aes.shiftRows(state);
    assertArrayEquals(state[0], actual[0]);
  }

  @Test
  void should_recover_state_on_mixColumns_then_invMixColumns() {
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(randomBlock());
    byte[][] actual = aes.invMixColumns(aes.mixColumns(state));
    assertArrayEquals(state, actual);
  }

  @Test
  void should_produce_correct_mixColumns_on_fips_known_vector() {
    // FIPS 197 Appendix B -- state before MixColumns at round 1
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = {
      {(byte) 0xd4, (byte) 0xe0, (byte) 0xb8, (byte) 0x1e},
      {(byte) 0xbf, (byte) 0xb4, (byte) 0x41, (byte) 0x27},
      {(byte) 0x5d, (byte) 0x52, (byte) 0x11, (byte) 0x98},
      {(byte) 0x30, (byte) 0xae, (byte) 0xf1, (byte) 0xe5}
    };
    byte[][] expected = {
      {(byte) 0x04, (byte) 0xe0, (byte) 0x48, (byte) 0x28},
      {(byte) 0x66, (byte) 0xcb, (byte) 0xf8, (byte) 0x06},
      {(byte) 0x81, (byte) 0x19, (byte) 0xd3, (byte) 0x26},
      {(byte) 0xe5, (byte) 0x9a, (byte) 0x7a, (byte) 0x4c}
    };
    assertArrayEquals(expected, aes.mixColumns(state));
  }

  @Test
  void should_recover_state_on_double_addRoundKey() {
    AES aes = AES.of(AESVariant.AES_128);
    byte[][] state = aes.toState(randomBlock());
    int[][] roundKey = new int[4][4];
    SecureRandom rng = new SecureRandom();
    for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) roundKey[r][c] = rng.nextInt(256);
    byte[][] actual = aes.addRoundKey(aes.addRoundKey(state, roundKey), roundKey);
    assertArrayEquals(state, actual);
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_produce_correct_number_of_round_keys_on_key_expansion(AESVariant variant) {
    AES aes = AES.of(variant);
    byte[] key = randomKey(variant);
    int[][][] roundKeys = aes.keyExpansion(key);
    assertEquals(variant.getRounds() + 1, roundKeys.length);
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_produce_distinct_round_keys_on_key_expansion(AESVariant variant) {
    AES aes = AES.of(variant);
    int[][][] roundKeys = aes.keyExpansion(randomKey(variant));
    assertFalse(Arrays.deepEquals(roundKeys[0], roundKeys[1]));
  }

  @Test
  void should_throw_on_null_block_encrypt() {
    AES aes = AES.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class, () -> aes.encrypt(null, randomKey(AESVariant.AES_128)));
  }

  @Test
  void should_throw_on_null_key_encrypt() {
    AES aes = AES.of(AESVariant.AES_128);
    assertThrows(IllegalArgumentException.class, () -> aes.encrypt(randomBlock(), null));
  }

  @Test
  void should_throw_on_wrong_block_size_encrypt() {
    AES aes = AES.of(AESVariant.AES_128);
    assertThrows(
        IllegalArgumentException.class,
        () -> aes.encrypt(SecureRandom.getSeed(15), randomKey(AESVariant.AES_128)));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_throw_on_wrong_key_size_encrypt(AESVariant variant) {
    AES aes = AES.of(variant);
    assertThrows(
        IllegalArgumentException.class,
        () -> aes.encrypt(randomBlock(), SecureRandom.getSeed(variant.getKeyBytes() - 1)));
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_decrypt_to_original_on_encrypt_then_decrypt(AESVariant variant) {
    AES aes = AES.of(variant);
    byte[] block = randomBlock();
    byte[] key = randomKey(variant);
    byte[] encrypted = aes.encrypt(block, key);
    byte[] actual = aes.decrypt(encrypted, key);
    assertArrayEquals(block, actual);
  }

  @ParameterizedTest
  @EnumSource(AESVariant.class)
  void should_produce_different_ciphertext_on_different_keys(AESVariant variant) {
    AES aes = AES.of(variant);
    byte[] block = randomBlock();
    assertFalse(
        Arrays.equals(
            aes.encrypt(block, randomKey(variant)), aes.encrypt(block, randomKey(variant))));
  }

  @RepeatedTest(10)
  void should_match_jdk_aes128_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] actual = AES.of(AESVariant.AES_128).encrypt(block, key);
    byte[] expected = jdkEncrypt(block, key);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_aes192_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] actual = AES.of(AESVariant.AES_192).encrypt(block, key);
    byte[] expected = jdkEncrypt(block, key);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_aes256_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] actual = AES.of(AESVariant.AES_256).encrypt(block, key);
    byte[] expected = jdkEncrypt(block, key);
    assertArrayEquals(expected, actual);
  }

  @Test
  void should_match_fips197_appendix_b_known_vector() {
    // FIPS 197 Appendix B
    byte[] block = {
      (byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8,
      (byte) 0x88, (byte) 0x5a, (byte) 0x30, (byte) 0x8d,
      (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2,
      (byte) 0xe0, (byte) 0x37, (byte) 0x07, (byte) 0x34
    };
    byte[] key = {
      (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
      (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
      (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
      (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c
    };
    byte[] expected = {
      (byte) 0x39, (byte) 0x25, (byte) 0x84, (byte) 0x1d,
      (byte) 0x02, (byte) 0xdc, (byte) 0x09, (byte) 0xfb,
      (byte) 0xdc, (byte) 0x11, (byte) 0x85, (byte) 0x97,
      (byte) 0x19, (byte) 0x6a, (byte) 0x0b, (byte) 0x32
    };
    byte[] actual = AES.of(AESVariant.AES_128).encrypt(block, key);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_aes128_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_128);
    byte[] encrypted = jdkEncrypt(block, key);
    byte[] actual = AES.of(AESVariant.AES_128).decrypt(encrypted, key);
    assertArrayEquals(block, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_aes192_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_192);
    byte[] encrypted = jdkEncrypt(block, key);
    byte[] actual = AES.of(AESVariant.AES_192).decrypt(encrypted, key);
    assertArrayEquals(block, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_aes256_decrypt_on_random_input() throws Exception {
    byte[] block = randomBlock();
    byte[] key = randomKey(AESVariant.AES_256);
    byte[] encrypted = jdkEncrypt(block, key);
    byte[] actual = AES.of(AESVariant.AES_256).decrypt(encrypted, key);
    assertArrayEquals(block, actual);
  }

  @Test
  void should_match_fips197_appendix_b_known_vector_decrypt() {
    byte[] expected = {
      (byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8,
      (byte) 0x88, (byte) 0x5a, (byte) 0x30, (byte) 0x8d,
      (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2,
      (byte) 0xe0, (byte) 0x37, (byte) 0x07, (byte) 0x34
    };
    byte[] key = {
      (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,
      (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
      (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,
      (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c
    };
    byte[] ciphertext = {
      (byte) 0x39, (byte) 0x25, (byte) 0x84, (byte) 0x1d,
      (byte) 0x02, (byte) 0xdc, (byte) 0x09, (byte) 0xfb,
      (byte) 0xdc, (byte) 0x11, (byte) 0x85, (byte) 0x97,
      (byte) 0x19, (byte) 0x6a, (byte) 0x0b, (byte) 0x32
    };
    byte[] actual = AES.of(AESVariant.AES_128).decrypt(ciphertext, key);
    assertArrayEquals(expected, actual);
  }
}
