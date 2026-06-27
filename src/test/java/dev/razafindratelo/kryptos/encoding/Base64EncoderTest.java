package dev.razafindratelo.kryptos.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Base64EncoderTest {

  private final Base64Encoder standard = Base64Encoder.standard();
  private final Base64Encoder urlSafe = Base64Encoder.urlSafe();

  static Stream<Arguments> provideInputs() {
    return Stream.of(
        Arguments.of((Object) "Man".getBytes()),
        Arguments.of((Object) "Ma".getBytes()),
        Arguments.of((Object) "M".getBytes()),
        Arguments.of((Object) "ManMan".getBytes()),
        Arguments.of((Object) "Hello, World!".getBytes()),
        Arguments.of((Object) new byte[] {0x00, (byte) 0xFF, 0x7F, (byte) 0x80}));
  }

  @Test
  void should_produce_TWFu_on_encoding_Man_bytes() {
    byte[] result = standard.encodeFullGroup('M', 'a', 'n');
    assertArrayEquals(new byte[] {'T', 'W', 'F', 'u'}, result);
  }

  @Test
  void should_produce_four_bytes_on_any_full_group_encoding() {
    byte[] result = standard.encodeFullGroup('M', 'a', 'n');
    assertEquals(4, result.length);
  }

  @Test
  void should_produce_two_padding_chars_on_one_byte_remainder() {
    byte[] result = standard.encodeOneByteRemainder('M');
    assertEquals('=', result[2]);
    assertEquals('=', result[3]);
  }

  @Test
  void should_produce_four_bytes_on_one_byte_remainder() {
    byte[] result = standard.encodeOneByteRemainder('M');
    assertEquals(4, result.length);
  }

  @Test
  void should_match_jdk_on_one_byte_remainder() {
    byte[] input = new byte[] {'M'};
    String ours = new String(standard.encodeOneByteRemainder('M'));
    String jdk = java.util.Base64.getEncoder().encodeToString(input);
    assertEquals(jdk, ours);
  }

  @Test
  void should_produce_one_padding_char_on_two_byte_remainder() {
    byte[] result = standard.encodeTwoByteRemainder('M', 'a');
    assertEquals('=', result[3]);
  }

  @Test
  void should_produce_four_bytes_on_two_byte_remainder() {
    byte[] result = standard.encodeTwoByteRemainder('M', 'a');
    assertEquals(4, result.length);
  }

  @Test
  void should_match_jdk_on_two_byte_remainder() {
    byte[] input = new byte[] {'M', 'a'};
    String ours = new String(standard.encodeTwoByteRemainder('M', 'a'));
    String jdk = java.util.Base64.getEncoder().encodeToString(input);
    assertEquals(jdk, ours);
  }

  @Test
  void should_produce_empty_array_on_zero_full_groups() {
    byte[] result = standard.encodeFullGroups(new byte[0], 0);
    assertEquals(0, result.length);
  }

  @Test
  void should_produce_four_bytes_per_group_on_full_groups_encoding() {
    byte[] input = "ManMan".getBytes();
    byte[] result = standard.encodeFullGroups(input, 2);
    assertEquals(8, result.length);
  }

  @Test
  void should_match_jdk_on_full_groups_encoding() {
    byte[] input = "Man".getBytes();
    String ours = new String(standard.encodeFullGroups(input, 1));
    String jdk = java.util.Base64.getEncoder().encodeToString(input);
    assertEquals(jdk, ours);
  }

  @Test
  void should_produce_empty_array_on_zero_remainder() {
    byte[] input = "Man".getBytes();
    byte[] result = standard.encodeRemainder(input, 1, 0);
    assertEquals(0, result.length);
  }

  @Test
  void should_produce_two_padding_chars_on_remainder_of_one() {
    byte[] input = "M".getBytes();
    byte[] result = standard.encodeRemainder(input, 0, 1);
    assertEquals('=', result[2]);
    assertEquals('=', result[3]);
  }

  @Test
  void should_produce_one_padding_char_on_remainder_of_two() {
    byte[] input = "Ma".getBytes();
    byte[] result = standard.encodeRemainder(input, 0, 2);
    assertEquals('=', result[3]);
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_input() {
    assertThrows(IllegalArgumentException.class, () -> standard.apply(null));
  }

  @Test
  void should_produce_empty_string_on_empty_input() {
    assertEquals("", standard.apply(new byte[0]));
  }

  @RepeatedTest(10)
  void should_match_jdk_standard_encoder_on_random_input() {
    byte[] randomBytes = SecureRandom.getSeed(32);

    String expected = Base64.getEncoder().encodeToString(randomBytes);
    String actual = Base64Encoder.standard().apply(randomBytes);

    assertEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_url_safe_encoder_on_random_input() {
    byte[] randomBytes = SecureRandom.getSeed(32);

    String actual = Base64Encoder.urlSafe().apply(randomBytes);
    String expected = Base64.getUrlEncoder().encodeToString(randomBytes);

    assertEquals(expected, actual);
  }

  @ParameterizedTest
  @MethodSource("provideInputs")
  void should_match_jdk_standard_encoder_on_arbitrary_input(byte[] input) {
    String ours = standard.apply(input);
    String jdk = java.util.Base64.getEncoder().encodeToString(input);
    assertEquals(jdk, ours);
  }

  @ParameterizedTest
  @MethodSource("provideInputs")
  void should_match_jdk_url_safe_encoder_on_arbitrary_input(byte[] input) {
    String ours = urlSafe.apply(input);
    String jdk = java.util.Base64.getUrlEncoder().encodeToString(input);
    assertEquals(jdk, ours);
  }
}
