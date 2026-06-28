package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class MD5Test {

  private final MD5 md5 = MD5.getInstance();

  static Stream<Arguments> provideKnownVectors() {
    return Stream.of(
        Arguments.of("", "d41d8cd98f00b204e9800998ecf8427e"),
        Arguments.of("a", "0cc175b9c0f1b6a831c399e269772661"),
        Arguments.of("abc", "900150983cd24fb0d6963f7d28e17f72"),
        Arguments.of("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        Arguments.of("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"));
  }

  private byte[] jdkMd5(byte[] input) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("MD5").digest(input);
  }

  @Test
  void should_wrap_bits_around_on_left_rotate() {
    // 0x80000001 = 10000000 00000000 00000000 00000001
    // rotl(3)    = 00000000 00000000 00000000 00001100 = 0x0000000C
    assertEquals(0x0000000C, md5.leftRotate(0x80000001, 3));
  }

  @Test
  void should_return_same_value_on_rotate_by_zero() {
    int value = 0x12345678;
    assertEquals(value, md5.leftRotate(value, 0));
  }

  @Test
  void should_return_same_value_on_rotate_by_32() {
    int value = 0x12345678;
    assertEquals(value, md5.leftRotate(value, 32));
  }

  @Test
  void should_select_c_bits_when_b_is_one_on_f() {
    // f(b,c,d) = (b & c) | (~b & d)
    // if b = 0xFFFFFFFF then f = c
    assertEquals(0xAAAAAAAA, md5.f(0xFFFFFFFF, 0xAAAAAAAA, 0x55555555));
  }

  @Test
  void should_select_d_bits_when_b_is_zero_on_f() {
    // if b = 0x00000000 then f = d
    assertEquals(0x55555555, md5.f(0x00000000, 0xAAAAAAAA, 0x55555555));
  }

  @Test
  void should_select_b_bits_when_d_is_one_on_g() {
    // g(b,c,d) = (b & d) | (c & ~d)
    // if d = 0xFFFFFFFF then g = b
    assertEquals(0xAAAAAAAA, md5.g(0xAAAAAAAA, 0x55555555, 0xFFFFFFFF));
  }

  @Test
  void should_return_xor_of_all_on_h() {
    assertEquals(0xAAAAAAAA ^ 0x55555555 ^ 0x12345678, md5.h(0xAAAAAAAA, 0x55555555, 0x12345678));
  }

  @Test
  void should_return_c_xor_b_or_not_d_on_i() {
    int b = 0xAAAAAAAA;
    int c = 0x55555555;
    int d = 0x12345678;
    assertEquals(c ^ (b | ~d), md5.i(b, c, d));
  }

  @Test
  void should_return_i_on_round_0() {
    assertEquals(5, md5.selectMessageWordIndex(0, 5));
  }

  @Test
  void should_return_5i_plus_1_mod_16_on_round_1() {
    assertEquals((5 * 5 + 1) % 16, md5.selectMessageWordIndex(1, 5));
  }

  @Test
  void should_return_3i_plus_5_mod_16_on_round_2() {
    assertEquals((3 * 5 + 5) % 16, md5.selectMessageWordIndex(2, 5));
  }

  @Test
  void should_return_7i_mod_16_on_round_3() {
    assertEquals((7 * 5) % 16, md5.selectMessageWordIndex(3, 5));
  }

  @Test
  void should_throw_illegal_argument_exception_on_invalid_round() {
    assertThrows(IllegalArgumentException.class, () -> md5.selectMessageWordIndex(4, 0));
  }

  @Test
  void should_produce_length_multiple_of_64_on_padding() {
    byte[] padded = md5.pad("abc".getBytes());

    assertEquals(0, padded.length % 64);
  }

  @Test
  void should_set_high_bit_after_message_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] padded = md5.pad(input);

    assertEquals((byte) 0x80, padded[input.length]);
  }

  @Test
  void should_store_message_length_in_bits_at_end_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] padded = md5.pad(input);
    long lengthBits =
        java.nio.ByteBuffer.wrap(padded, padded.length - 8, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .getLong();
    assertEquals(input.length * 8L, lengthBits);
  }

  @Test
  void should_produce_two_blocks_on_input_longer_than_55_bytes() {
    byte[] input = new byte[56];
    byte[] padded = md5.pad(input);
    assertEquals(128, padded.length);
  }

  @Test
  void should_produce_16_words_on_message_schedule() {
    byte[] block = new byte[64];
    int[] schedule = md5.toMessageSchedule(block);
    assertEquals(16, schedule.length);
  }

  @Test
  void should_read_words_in_little_endian_on_message_schedule() {
    byte[] block = new byte[64];
    block[0] = 0x01;
    block[1] = 0x02;
    block[2] = 0x03;
    block[3] = 0x04;
    int[] schedule = md5.toMessageSchedule(block);
    // little-endian: 0x04030201
    assertEquals(0x04030201, schedule[0]);
  }

  @Test
  void should_produce_16_bytes_on_digest() {
    int[] state = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    byte[] digest = md5.toDigest(state);
    assertEquals(16, digest.length);
  }

  @Test
  void should_write_state_in_little_endian_on_digest() {
    int[] state = {0x01020304, 0, 0, 0};
    byte[] digest = md5.toDigest(state);
    // little-endian: first word 0x01020304 -> bytes 04 03 02 01
    assertEquals((byte) 0x04, digest[0]);
    assertEquals((byte) 0x03, digest[1]);
    assertEquals((byte) 0x02, digest[2]);
    assertEquals((byte) 0x01, digest[3]);
  }

  @Test
  void should_produce_32_char_hex_string_on_128_bit_digest() {
    byte[] digest = new byte[16];
    assertEquals(32, md5.toHexString(digest).length());
  }

  @Test
  void should_produce_lowercase_hex_on_hex_string() {
    byte[] digest = new byte[] {(byte) 0xAB, (byte) 0xCD};
    assertEquals("abcd", md5.toHexString(digest));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_input() {
    assertThrows(IllegalArgumentException.class, () -> md5.apply(null));
  }

  @Test
  void should_produce_16_bytes_on_any_input() {
    assertEquals(16, md5.apply("abc".getBytes()).length);
  }

  @ParameterizedTest
  @MethodSource("provideKnownVectors")
  void should_match_known_md5_vector(String input, String expectedHex) {
    String actual = md5.toHexString(md5.apply(input.getBytes()));

    assertEquals(expectedHex, actual);
  }

  @ParameterizedTest
  @MethodSource("provideKnownVectors")
  void should_match_jdk_on_known_vectors(String input) throws NoSuchAlgorithmException {
    assertArrayEquals(jdkMd5(input.getBytes()), md5.apply(input.getBytes()));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_random_input() throws NoSuchAlgorithmException {
    byte[] randomBytes = SecureRandom.getSeed(32);

    assertArrayEquals(jdkMd5(randomBytes), md5.apply(randomBytes));
  }

  @Test
  void should_produce_different_digests_on_different_inputs() {
    byte[] a = md5.apply("abc".getBytes());
    byte[] b = md5.apply("abd".getBytes());

    assertFalse(Arrays.equals(a, b));
  }

  @Test
  void should_produce_same_digest_on_same_input() {
    byte[] input = "abc".getBytes();

    assertArrayEquals(md5.apply(input), md5.apply(input));
  }
}
