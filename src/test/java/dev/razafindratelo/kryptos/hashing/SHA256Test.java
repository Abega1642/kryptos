package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
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

class SHA256Test {

  private final SHA256 sha256 = SHA256.getInstance();

  static Stream<Arguments> provideKnownVectors() throws NoSuchAlgorithmException {
    return Stream.of("", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        .map(
            input -> {
              try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes());
                StringBuilder hex = new StringBuilder();
                for (byte b : digest) hex.append(String.format("%02x", b & 0xFF));
                return Arguments.of(input, hex.toString());
              } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
              }
            });
  }

  private byte[] jdkSha256(byte[] input) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("SHA-256").digest(input);
  }

  @Test
  void should_wrap_bits_around_on_right_rotate() {
    // 0x00000001 = 00000000 00000000 00000000 00000001
    // rotr(1)    = 10000000 00000000 00000000 00000000 = 0x80000000
    assertEquals(0x80000000, sha256.rightRotate(0x00000001, 1));
  }

  @Test
  void should_return_same_value_on_rotate_by_zero() {
    int value = 0x12345678;
    assertEquals(value, sha256.rightRotate(value, 0));
  }

  @Test
  void should_return_same_value_on_rotate_by_32() {
    int value = 0x12345678;
    assertEquals(value, sha256.rightRotate(value, 32));
  }

  @Test
  void should_select_f_bits_when_e_is_all_ones_on_ch() {
    assertEquals(0xAAAAAAAA, sha256.ch(0xFFFFFFFF, 0xAAAAAAAA, 0x55555555));
  }

  @Test
  void should_select_g_bits_when_e_is_all_zeros_on_ch() {
    assertEquals(0x55555555, sha256.ch(0x00000000, 0xAAAAAAAA, 0x55555555));
  }

  @Test
  void should_return_majority_vote_on_maj() {
    // a=1111, b=1111, c=0000 -> majority is 1111
    assertEquals(0xFFFFFFFF, sha256.maj(0xFFFFFFFF, 0xFFFFFFFF, 0x00000000));
  }

  @Test
  void should_return_zero_when_majority_is_zero_on_maj() {
    assertEquals(0x00000000, sha256.maj(0x00000000, 0x00000000, 0xFFFFFFFF));
  }

  @Test
  void should_produce_correct_sigma0_on_known_value() {
    int a = 0x6a09e667;

    int expected = sha256.rightRotate(a, 2) ^ sha256.rightRotate(a, 13) ^ sha256.rightRotate(a, 22);

    assertEquals(expected, sha256.sigma0(a));
  }

  @Test
  void should_produce_correct_sigma1_on_known_value() {
    int e = 0x510e527f;

    int expected = sha256.rightRotate(e, 6) ^ sha256.rightRotate(e, 11) ^ sha256.rightRotate(e, 25);

    assertEquals(expected, sha256.sigma1(e));
  }

  @Test
  void should_produce_correct_little_sigma0_on_known_value() {
    int x = 0x6a09e667;

    int expected = sha256.rightRotate(x, 7) ^ sha256.rightRotate(x, 18) ^ (x >>> 3);

    assertEquals(expected, sha256.littleSigma0(x));
  }

  @Test
  void should_produce_correct_little_sigma1_on_known_value() {
    int x = 0x6a09e667;

    int expected = sha256.rightRotate(x, 17) ^ sha256.rightRotate(x, 19) ^ (x >>> 10);

    assertEquals(expected, sha256.littleSigma1(x));
  }

  @Test
  void should_produce_64_words_on_message_schedule() {
    byte[] block = new byte[64];

    int[] actual = sha256.buildMessageSchedule(block);

    assertEquals(64, actual.length);
  }

  @Test
  void should_read_first_16_words_in_big_endian_on_message_schedule() {
    byte[] block = new byte[64];
    block[0] = 0x01;
    block[1] = 0x02;
    block[2] = 0x03;
    block[3] = 0x04;
    int[] actual = sha256.buildMessageSchedule(block);

    assertEquals(0x01020304, actual[0]);
  }

  @Test
  void should_expand_words_beyond_index_15_on_message_schedule() {
    byte[] block = new byte[64];
    block[0] = 0x01;
    int[] actual = sha256.buildMessageSchedule(block);
    // words at index >= 16 must differ from zero (expansion happened)
    assertFalse(Arrays.stream(actual).skip(16).allMatch(w -> w == 0));
  }

  @Test
  void should_produce_length_multiple_of_64_on_padding() {
    byte[] actual = sha256.pad("abc".getBytes());

    assertEquals(0, actual.length % 64);
  }

  @Test
  void should_set_high_bit_after_message_on_padding() {
    byte[] input = "abc".getBytes();

    byte[] actual = sha256.pad(input);

    assertEquals((byte) 0x80, actual[input.length]);
  }

  @Test
  void should_produce_two_blocks_on_input_longer_than_55_bytes() {
    byte[] actual = sha256.pad(new byte[56]);

    assertEquals(128, actual.length);
  }

  @Test
  void should_produce_32_bytes_on_digest() {
    int[] state = new int[8];

    assertEquals(32, sha256.toDigest(state).length);
  }

  @Test
  void should_write_state_in_big_endian_on_digest() {
    int[] state = {0x01020304, 0, 0, 0, 0, 0, 0, 0};

    byte[] actual = sha256.toDigest(state);

    assertEquals((byte) 0x01, actual[0]);
    assertEquals((byte) 0x02, actual[1]);
    assertEquals((byte) 0x03, actual[2]);
    assertEquals((byte) 0x04, actual[3]);
  }

  @Test
  void should_produce_64_char_hex_string_on_256_bit_digest() {
    byte[] digest = new byte[32];

    assertEquals(64, sha256.toHexString(digest).length());
  }

  @Test
  void should_produce_lowercase_hex_on_hex_string() {
    byte[] digest = new byte[] {(byte) 0xAB, (byte) 0xCD};
    assertEquals("abcd", sha256.toHexString(digest));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_input() {
    assertThrows(IllegalArgumentException.class, () -> sha256.apply(null));
  }

  @Test
  void should_produce_32_bytes_on_any_input() {
    assertEquals(32, sha256.apply("abc".getBytes()).length);
  }

  @Test
  void should_produce_same_digest_on_same_input() {
    byte[] input = "abc".getBytes();

    assertArrayEquals(sha256.apply(input), sha256.apply(input));
  }

  @Test
  void should_produce_different_digests_on_different_inputs() {
    byte[] a = sha256.apply("abc".getBytes());
    byte[] b = sha256.apply("abd".getBytes());

    assertFalse(Arrays.equals(a, b));
  }

  @ParameterizedTest
  @MethodSource("provideKnownVectors")
  void should_match_known_sha256_vector(String input, String expectedHex) {
    String actual = sha256.toHexString(sha256.apply(input.getBytes()));

    assertEquals(expectedHex, actual);
  }

  @ParameterizedTest
  @MethodSource("provideKnownVectors")
  void should_match_jdk_on_known_vectors(String input) throws NoSuchAlgorithmException {
    byte[] actual = sha256.apply(input.getBytes());
    byte[] expected = jdkSha256(input.getBytes());

    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_on_random_input() throws NoSuchAlgorithmException {
    byte[] randomBytes = SecureRandom.getSeed(32);

    byte[] actual = sha256.apply(randomBytes);
    byte[] expected = jdkSha256(randomBytes);

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_consistent_sha256_on_pdf() throws IOException, NoSuchAlgorithmException {
    var resource = getClass().getResource("/assets/test-base64.pdf");
    assertNotNull(resource);
    byte[] pdfBytes = resource.openStream().readAllBytes();

    byte[] actual = sha256.apply(pdfBytes);
    byte[] expected = jdkSha256(pdfBytes);

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_consistent_sha256_on_png() throws IOException, NoSuchAlgorithmException {
    var resource = getClass().getResource("/assets/test-base64.png");
    assertNotNull(resource);
    byte[] pngBytes = resource.openStream().readAllBytes();

    byte[] actual = sha256.apply(pngBytes);
    byte[] expected = jdkSha256(pngBytes);

    assertArrayEquals(expected, actual);
  }
}
