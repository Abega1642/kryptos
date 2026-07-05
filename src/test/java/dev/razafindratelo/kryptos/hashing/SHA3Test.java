package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class SHA3Test {

  private final SHA3 sha3 = SHA3.getInstance();

  private byte[] jdkSha3(byte[] input) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance("SHA3-256").digest(input);
  }

  @Test
  void should_produce_length_multiple_of_136_on_padding() {
    byte[] actual = sha3.pad("abc".getBytes());
    assertEquals(0, actual.length % 136);
  }

  @Test
  void should_set_domain_suffix_after_message_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] actual = sha3.pad(input);
    assertEquals((byte) 0x06, actual[input.length]);
  }

  @Test
  void should_set_padding_end_at_last_byte_on_padding() {
    byte[] actual = sha3.pad("abc".getBytes());
    assertEquals((byte) 0x80, actual[actual.length - 1]);
  }

  @Test
  void should_produce_two_blocks_on_input_longer_than_135_bytes() {
    byte[] actual = sha3.pad(new byte[136]);
    assertEquals(272, actual.length);
  }

  @Test
  void should_preserve_original_bytes_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] actual = sha3.pad(input);
    assertEquals((byte) 'a', actual[0]);
    assertEquals((byte) 'b', actual[1]);
    assertEquals((byte) 'c', actual[2]);
  }

  @Test
  void should_wrap_bits_around_on_rotate_left() {
    // 0x8000000000000000 rotated left by 1 = 0x0000000000000001
    assertEquals(0x0000000000000001L, sha3.rotateLeft(0x8000000000000000L, 1));
  }

  @Test
  void should_return_same_value_on_rotate_by_zero() {
    long value = 0x123456789abcdef0L;
    assertEquals(value, sha3.rotateLeft(value, 0));
  }

  @Test
  void should_return_same_value_on_rotate_by_64() {
    long value = 0x123456789abcdef0L;
    assertEquals(value, sha3.rotateLeft(value, 64));
  }

  @Test
  void should_xor_block_into_state_in_little_endian() {
    long[] state = new long[25];
    byte[] block = new byte[136];
    block[0] = 0x01;
    block[1] = 0x02;
    block[2] = 0x03;
    block[3] = 0x04;
    block[4] = 0x05;
    block[5] = 0x06;
    block[6] = 0x07;
    block[7] = 0x08;
    long[] actual = sha3.toState(block, state);
    // little-endian: 0x0807060504030201
    assertEquals(0x0807060504030201L, actual[0]);
  }

  @Test
  void should_xor_into_existing_state_on_toState() {
    long[] state = new long[25];
    state[0] = 0x00000000000000FFL;
    byte[] block = new byte[136];
    block[0] = (byte) 0xFF;
    long[] actual = sha3.toState(block, state);
    assertEquals(0x0000000000000000L, actual[0]);
  }

  @Test
  void should_produce_25_lanes_on_theta() {
    long[] state = new long[25];
    long[] actual = sha3.theta(state);
    assertEquals(25, actual.length);
  }

  @Test
  void should_not_mutate_input_on_theta() {
    long[] state = new long[25];
    state[0] = 0x123456789abcdef0L;
    long[] original = state.clone();
    sha3.theta(state);
    assertArrayEquals(original, state);
  }

  @Test
  void should_return_all_zeros_on_all_zero_state_theta() {
    long[] state = new long[25];
    long[] actual = sha3.theta(state);
    assertTrue(Arrays.stream(actual).allMatch(lane -> lane == 0L));
  }

  @Test
  void should_produce_25_lanes_on_rhoPi() {
    long[] state = new long[25];
    long[] actual = sha3.rhoPi(state);
    assertEquals(25, actual.length);
  }

  @Test
  void should_return_all_zeros_on_all_zero_state_rhoPi() {
    long[] state = new long[25];
    long[] actual = sha3.rhoPi(state);
    assertTrue(Arrays.stream(actual).allMatch(lane -> lane == 0L));
  }

  @Test
  void should_produce_25_lanes_on_chi() {
    long[] state = new long[25];
    long[] actual = sha3.chi(state);
    assertEquals(25, actual.length);
  }

  @Test
  void should_produce_different_state_on_non_zero_input_rhoPi() {
    long[] state = new long[25];
    state[1] = 0x123456789abcdef0L;
    long[] actual = sha3.rhoPi(state);
    assertFalse(Arrays.equals(state, actual));
  }

  @Test
  void should_produce_different_state_on_non_zero_input_chi() {
    long[] state = new long[25];
    state[0] = 0x123456789abcdef0L;
    long[] actual = sha3.chi(state);
    assertFalse(Arrays.equals(state, actual));
  }

  @Test
  void should_return_all_zeros_on_all_zero_state_chi() {
    long[] state = new long[25];
    long[] actual = sha3.chi(state);
    assertTrue(Arrays.stream(actual).allMatch(lane -> lane == 0L));
  }

  @Test
  void should_xor_round_constant_into_first_lane_on_iota() {
    long[] state = new long[25];
    long[] actual = sha3.iota(state, 0);
    // RC[0] = 0x0000000000000001
    assertEquals(0x0000000000000001L, actual[0]);
  }

  @Test
  void should_not_affect_other_lanes_on_iota() {
    long[] state = new long[25];
    long[] actual = sha3.iota(state, 0);
    for (int i = 1; i < 25; i++) {
      assertEquals(0L, actual[i]);
    }
  }

  @Test
  void should_not_mutate_input_on_iota() {
    long[] state = new long[25];
    long[] original = state.clone();
    sha3.iota(state, 0);
    assertArrayEquals(original, state);
  }

  @Test
  void should_produce_25_lanes_on_keccakF() {
    long[] state = new long[25];
    long[] actual = sha3.keccakF(state);
    assertEquals(25, actual.length);
  }

  @Test
  void should_not_mutate_input_on_keccakF() {
    long[] state = new long[25];
    state[0] = 0x123456789abcdef0L;
    long[] original = state.clone();
    sha3.keccakF(state);
    assertArrayEquals(original, state);
  }

  @Test
  void should_produce_non_zero_state_on_non_zero_input_keccakF() {
    long[] state = new long[25];
    state[0] = 0x0000000000000001L;
    long[] actual = sha3.keccakF(state);
    assertFalse(Arrays.stream(actual).allMatch(lane -> lane == 0L));
  }

  @Test
  void should_produce_32_bytes_on_squeeze() {
    long[] state = new long[25];
    byte[] actual = sha3.squeeze(state);
    assertEquals(32, actual.length);
  }

  @Test
  void should_extract_bytes_in_little_endian_on_squeeze() {
    long[] state = new long[25];
    state[0] = 0x0807060504030201L;
    byte[] actual = sha3.squeeze(state);
    assertEquals((byte) 0x01, actual[0]);
    assertEquals((byte) 0x02, actual[1]);
    assertEquals((byte) 0x03, actual[2]);
    assertEquals((byte) 0x04, actual[3]);
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_input() {
    assertThrows(IllegalArgumentException.class, () -> sha3.apply(null));
  }

  @Test
  void should_produce_32_bytes_on_any_input() {
    assertEquals(32, sha3.apply("abc".getBytes()).length);
  }

  @Test
  void should_produce_same_digest_on_same_input() {
    byte[] input = "abc".getBytes();
    assertArrayEquals(sha3.apply(input), sha3.apply(input));
  }

  @Test
  void should_produce_different_digests_on_different_inputs() {
    byte[] a = sha3.apply("abc".getBytes());
    byte[] b = sha3.apply("abd".getBytes());
    assertFalse(Arrays.equals(a, b));
  }

  @Test
  void should_match_jdk_on_empty_input() throws NoSuchAlgorithmException {
    byte[] actual = sha3.apply(new byte[0]);
    byte[] expected = jdkSha3(new byte[0]);
    assertArrayEquals(expected, actual);
  }

  @Test
  void should_match_jdk_on_abc() throws NoSuchAlgorithmException {
    byte[] actual = sha3.apply("abc".getBytes());
    byte[] expected = jdkSha3("abc".getBytes());
    assertArrayEquals(expected, actual);
  }

  @Test
  void should_match_jdk_on_long_input() throws NoSuchAlgorithmException {
    byte[] input = new byte[200];
    byte[] actual = sha3.apply(input);
    byte[] expected = jdkSha3(input);
    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_on_random_input() throws NoSuchAlgorithmException {
    byte[] randomBytes = SecureRandom.getSeed(32);
    byte[] actual = sha3.apply(randomBytes);
    byte[] expected = jdkSha3(randomBytes);
    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_consistent_sha256_on_pdf() throws IOException, NoSuchAlgorithmException {
    var resource = getClass().getResource("/assets/test-base64.pdf");
    assertNotNull(resource);
    byte[] pdfBytes = resource.openStream().readAllBytes();

    byte[] actual = sha3.apply(pdfBytes);
    byte[] expected = jdkSha3(pdfBytes);

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_consistent_sha256_on_png() throws IOException, NoSuchAlgorithmException {
    var resource = getClass().getResource("/assets/test-base64.png");
    assertNotNull(resource);
    byte[] pngBytes = resource.openStream().readAllBytes();

    byte[] actual = sha3.apply(pngBytes);
    byte[] expected = jdkSha3(pngBytes);

    assertArrayEquals(expected, actual);
  }
}
