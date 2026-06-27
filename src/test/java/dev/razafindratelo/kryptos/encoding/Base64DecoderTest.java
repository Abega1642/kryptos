package dev.razafindratelo.kryptos.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Base64DecoderTest {

  private final Base64Decoder standard = Base64Decoder.standard();
  private final Base64Decoder urlSafe = Base64Decoder.urlSafe();

  static Stream<Arguments> provideInputs() {
    return Stream.of(
        Arguments.of("TWFu"),
        Arguments.of("TWE="),
        Arguments.of("TQ=="),
        Arguments.of("TWFuTWFu"),
        Arguments.of("SGVsbG8sIFdvcmxkIQ=="));
  }

  static Stream<Arguments> provideUrlSafeInputs() {
    return Stream.of(Arguments.of("TWFu"), Arguments.of("TWE="), Arguments.of("TQ=="));
  }

  static Stream<Arguments> provideRawInputs() {
    return Stream.of(
        Arguments.of((Object) "Man".getBytes()),
        Arguments.of((Object) "Ma".getBytes()),
        Arguments.of((Object) "M".getBytes()),
        Arguments.of((Object) "Hello, World!".getBytes()),
        Arguments.of((Object) new byte[] {0x00, (byte) 0xFF, 0x7F, (byte) 0x80}));
  }

  @Test
  void should_count_zero_padding_on_input_with_no_padding() {
    assertEquals(0, standard.countPadding("TWFu"));
  }

  @Test
  void should_count_one_padding_on_input_with_one_padding() {
    assertEquals(1, standard.countPadding("TWE="));
  }

  @Test
  void should_count_two_paddings_on_input_with_two_paddings() {
    assertEquals(2, standard.countPadding("TQ=="));
  }

  @Test
  void should_reconstruct_Man_bytes_on_decoding_TWFu_indices() {
    // T=19, W=22, F=5, u=46
    byte[] actual = standard.decodeFullGroup(19, 22, 5, 46);

    assertArrayEquals("Man".getBytes(), actual);
  }

  @Test
  void should_produce_three_bytes_on_full_group_decoding() {
    byte[] actual = standard.decodeFullGroup(19, 22, 5, 46);

    assertEquals(3, actual.length);
  }

  @Test
  void should_produce_one_byte_on_one_byte_remainder_decoding() {
    byte[] actual = standard.decodeOneByteRemainder(19, 0);

    assertEquals(1, actual.length);
  }

  @Test
  void should_match_jdk_on_one_byte_remainder_decoding() {
    // "TQ==" is Base64 for "M": T=19, Q=16
    byte[] actual = standard.decodeOneByteRemainder(19, 16);
    byte[] expected = Base64.getDecoder().decode("TQ==");

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_two_bytes_on_two_byte_remainder_decoding() {
    // "TWE=" is Base64 for "Ma"
    byte[] actual = standard.decodeTwoByteRemainder(19, 22, 4);

    assertEquals(2, actual.length);
  }

  @Test
  void should_match_jdk_on_two_byte_remainder_decoding() {
    // "TWE=" is Base64 for "Ma"
    byte[] actual = standard.decodeTwoByteRemainder(19, 22, 4);
    byte[] expected = Base64.getDecoder().decode("TWE=");

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_produce_empty_array_on_zero_full_groups() {
    byte[] actual = standard.decodeFullGroups(new byte[0], 0);

    assertEquals(0, actual.length);
  }

  @Test
  void should_produce_three_bytes_per_group_on_full_groups_decoding() {
    byte[] input = "TWFuTWFu".getBytes();

    byte[] actual = standard.decodeFullGroups(input, 2);

    assertEquals(6, actual.length);
  }

  @Test
  void should_match_jdk_on_full_groups_decoding() {
    byte[] input = "TWFu".getBytes();

    byte[] actual = standard.decodeFullGroups(input, 1);
    byte[] expected = Base64.getDecoder().decode("TWFu");

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_input() {
    assertThrows(IllegalArgumentException.class, () -> standard.apply(null));
  }

  @Test
  void should_produce_empty_array_on_empty_input() {
    assertArrayEquals(new byte[0], standard.apply(""));
  }

  @Test
  void should_throw_illegal_argument_exception_on_invalid_length_input() {
    assertThrows(IllegalArgumentException.class, () -> standard.apply("TWF"));
  }

  @RepeatedTest(10)
  void should_match_jdk_standard_decoder_on_random_input() {
    byte[] randomBytes = SecureRandom.getSeed(32);
    String encoded = Base64.getEncoder().encodeToString(randomBytes);

    byte[] actual = standard.apply(encoded);
    byte[] expected = Base64.getDecoder().decode(encoded);

    assertArrayEquals(expected, actual);
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
  void should_match_jdk_standard_decoder_on_arbitrary_input(String input) {
    byte[] ours = standard.apply(input);
    byte[] expected = Base64.getDecoder().decode(input);

    assertArrayEquals(expected, ours);
  }

  @ParameterizedTest
  @MethodSource("provideUrlSafeInputs")
  void should_match_jdk_url_safe_decoder_on_arbitrary_input(String input) {
    byte[] ours = urlSafe.apply(input);
    byte[] expected = Base64.getUrlDecoder().decode(input);

    assertArrayEquals(expected, ours);
  }

  @ParameterizedTest
  @MethodSource("provideRawInputs")
  void should_be_inverse_of_encoder_on_arbitrary_input(byte[] rawInput) {
    String encoded = Base64Encoder.standard().apply(rawInput);

    byte[] decoded = standard.apply(encoded);

    assertArrayEquals(rawInput, decoded);
  }

  @Test
  void should_throw_illegal_argument_exception_on_invalid_character_in_full_group() {
    assertThrows(IllegalArgumentException.class, () -> standard.apply("TW?u"));
  }

  @Test
  void should_throw_illegal_argument_exception_on_invalid_character_in_remainder() {
    assertThrows(IllegalArgumentException.class, () -> standard.apply("TWFu?Q=="));
  }

  @Test
  void should_throw_illegal_argument_exception_on_url_safe_character_in_standard_decoder() {
    // '-' and '_' are valid in URL-safe but invalid in standard
    assertThrows(IllegalArgumentException.class, () -> standard.apply("TW-u"));
    assertThrows(IllegalArgumentException.class, () -> standard.apply("TW_u"));
  }

  @Test
  void should_throw_illegal_argument_exception_on_standard_character_in_url_safe_decoder() {
    // '+' and '/' are valid in standard but invalid in URL-safe
    assertThrows(IllegalArgumentException.class, () -> urlSafe.apply("TW+u"));
    assertThrows(IllegalArgumentException.class, () -> urlSafe.apply("TW/u"));
  }

  @Test
  void should_match_jdk_on_pdf_decoding() throws IOException {
    var resource = getClass().getResource("/assets/test-base64.pdf");
    assertNotNull(resource);
    byte[] pdfBytes = resource.openStream().readAllBytes();
    String encoded = Base64.getEncoder().encodeToString(pdfBytes);

    byte[] actual = standard.apply(encoded);
    byte[] expected = Base64.getDecoder().decode(encoded);

    assertArrayEquals(expected, actual);
  }

  @Test
  void should_match_jdk_on_png_decoding() throws IOException {
    var resource = getClass().getResource("/assets/test-base64.png");
    assertNotNull(resource);
    byte[] pngBytes = resource.openStream().readAllBytes();
    String encoded = Base64.getEncoder().encodeToString(pngBytes);

    byte[] actual = standard.apply(encoded);
    byte[] expected = Base64.getDecoder().decode(encoded);

    assertArrayEquals(expected, actual);
  }
}
