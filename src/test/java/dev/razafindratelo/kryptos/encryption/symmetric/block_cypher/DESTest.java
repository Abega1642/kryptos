package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class DESTest {

  private final DES des = DES.getInstance();

  private byte[] jdkEncrypt(byte[] block, byte[] key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));

    return cipher.doFinal(block);
  }

  private byte[] jdkDecrypt(byte[] block, byte[] key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "DES"));

    return cipher.doFinal(block);
  }

  @Test
  void should_throw_on_null_block() {
    byte[] key = SecureRandom.getSeed(8);
    assertThrows(IllegalArgumentException.class, () -> des.apply(null, key));
  }

  @Test
  void should_throw_on_null_key() {
    byte[] block = SecureRandom.getSeed(8);
    assertThrows(IllegalArgumentException.class, () -> des.apply(block, null));
  }

  @Test
  void should_throw_on_block_not_8_bytes() {
    byte[] block = SecureRandom.getSeed(7);
    byte[] key = SecureRandom.getSeed(8);
    assertThrows(IllegalArgumentException.class, () -> des.apply(block, key));
  }

  @Test
  void should_throw_on_key_not_8_bytes() {
    byte[] block = SecureRandom.getSeed(8);
    byte[] key = SecureRandom.getSeed(7);
    assertThrows(IllegalArgumentException.class, () -> des.apply(block, key));
  }

  @Test
  void should_produce_output_length_matching_table_on_permute() {
    int[] table = {1, 2, 3, 4};
    long input = 0xFFL;
    long actual = des.permute(input, table, 8);
    assertEquals(0xFL, actual);
  }

  @Test
  void should_produce_16_subkeys_on_key_schedule() {
    byte[] key = SecureRandom.getSeed(8);
    long[] actual = des.generateSubkeys(key);
    assertEquals(16, actual.length);
  }

  @Test
  void should_produce_distinct_subkeys_on_key_schedule() {
    byte[] key = SecureRandom.getSeed(8);
    long[] subkeys = des.generateSubkeys(key);
    long first = subkeys[0];
    assertFalse(Arrays.stream(subkeys).skip(1).allMatch(k -> k == first));
  }

  @Test
  void should_produce_48_bit_subkeys_on_key_schedule() {
    byte[] key = SecureRandom.getSeed(8);
    long[] subkeys = des.generateSubkeys(key);
    for (long subkey : subkeys) {
      assertEquals(0L, subkey & 0xFFFF000000000000L);
    }
  }

  @Test
  void should_produce_48_bit_output_on_expand() {
    long actual = des.expand(0xFFFFFFFFL);
    assertEquals(0L, actual & 0xFFFF000000000000L);
  }

  @Test
  void should_produce_32_bit_output_on_s_boxes() {
    long actual = des.applySBoxes(0xFFFFFFFFFFFFL);
    assertEquals(0L, actual & 0xFFFFFFFF00000000L);
  }

  @Test
  void should_produce_non_zero_output_on_non_zero_input_s_boxes() {
    long actual = des.applySBoxes(0x123456789ABCL);
    assertNotEquals(0L, actual);
  }

  @Test
  void should_swap_halves_on_feistel_round() {
    long left = 0x12345678L;
    long right = 0xABCDEF01L;
    long subkey = 0L;
    long[] actual = des.feistelRound(left, right, subkey);
    assertEquals(right, actual[0]);
  }

  @Test
  void should_produce_two_halves_on_feistel_round() {
    long[] actual = des.feistelRound(0x12345678L, 0xABCDEF01L, 0L);
    assertEquals(2, actual.length);
  }

  @Test
  void should_produce_8_bytes_on_encrypt_block() {
    byte[] block = SecureRandom.getSeed(8);
    long[] subkeys = des.generateSubkeys(SecureRandom.getSeed(8));
    assertEquals(8, des.encryptBlock(block, subkeys).length);
  }

  @Test
  void should_decrypt_to_original_on_encrypt_then_decrypt() {
    byte[] block = SecureRandom.getSeed(8);
    byte[] key = SecureRandom.getSeed(8);
    long[] subkeys = des.generateSubkeys(key);
    byte[] encrypted = des.encryptBlock(block, subkeys);
    byte[] actual = des.decryptBlock(encrypted, subkeys);
    assertArrayEquals(block, actual);
  }

  @Test
  void should_produce_different_ciphertext_on_different_keys() {
    byte[] block = SecureRandom.getSeed(8);
    byte[] key1 = SecureRandom.getSeed(8);
    byte[] key2 = SecureRandom.getSeed(8);
    assertFalse(
        Arrays.equals(
            des.encryptBlock(block, des.generateSubkeys(key1)),
            des.encryptBlock(block, des.generateSubkeys(key2))));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_random_input() throws Exception {
    byte[] block = SecureRandom.getSeed(8);
    byte[] key = SecureRandom.getSeed(8);
    byte[] actual = des.apply(block, key);
    byte[] expected = jdkEncrypt(block, key);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_to_original_on_random_input() throws Exception {
    byte[] block = SecureRandom.getSeed(8);
    byte[] key = SecureRandom.getSeed(8);
    byte[] encrypted = des.apply(block, key);
    byte[] actual = des.decryptBlock(encrypted, des.generateSubkeys(key));
    byte[] expected = jdkDecrypt(encrypted, key);
    assertArrayEquals(expected, actual);
  }
}
