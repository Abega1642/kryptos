package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class HashingUtilsTest {

  static Stream<Arguments> provideStateAndByteOrder() {
    return Stream.of(
        Arguments.of(new int[4], ByteOrder.LITTLE_ENDIAN),
        Arguments.of(new int[8], ByteOrder.BIG_ENDIAN),
        Arguments.of(new int[16], ByteOrder.BIG_ENDIAN));
  }

  @Test
  void should_produce_length_multiple_of_64_on_little_endian_padding() {
    byte[] actual = HashingUtils.pad("abc".getBytes(), ByteOrder.LITTLE_ENDIAN);

    assertEquals(0, actual.length % 64);
  }

  @Test
  void should_produce_length_multiple_of_64_on_big_endian_padding() {
    byte[] actual = HashingUtils.pad("abc".getBytes(), ByteOrder.BIG_ENDIAN);

    assertEquals(0, actual.length % 64);
  }

  @Test
  void should_set_high_bit_after_message_on_padding() {
    byte[] input = "abc".getBytes();

    byte[] actual = HashingUtils.pad(input, ByteOrder.BIG_ENDIAN);

    assertEquals((byte) 0x80, actual[input.length]);
  }

  @Test
  void should_store_message_length_in_bits_as_little_endian_at_end_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] actual = HashingUtils.pad(input, ByteOrder.LITTLE_ENDIAN);

    long lengthBits =
        ByteBuffer.wrap(actual, actual.length - 8, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();

    assertEquals(input.length * 8L, lengthBits);
  }

  @Test
  void should_store_message_length_in_bits_as_big_endian_at_end_on_padding() {
    byte[] input = "abc".getBytes();
    byte[] actual = HashingUtils.pad(input, ByteOrder.BIG_ENDIAN);

    long lengthBits =
        ByteBuffer.wrap(actual, actual.length - 8, 8).order(ByteOrder.BIG_ENDIAN).getLong();

    assertEquals(input.length * 8L, lengthBits);
  }

  @Test
  void should_produce_two_blocks_on_input_longer_than_55_bytes() {
    byte[] actual = HashingUtils.pad(new byte[56], ByteOrder.BIG_ENDIAN);

    assertEquals(128, actual.length);
  }

  @Test
  void should_preserve_original_input_bytes_on_padding() {
    byte[] input = "abc".getBytes();

    byte[] actual = HashingUtils.pad(input, ByteOrder.BIG_ENDIAN);

    assertEquals((byte) 'a', actual[0]);
    assertEquals((byte) 'b', actual[1]);
    assertEquals((byte) 'c', actual[2]);
  }

  @Test
  void should_produce_one_block_on_64_byte_input() {
    byte[] input = new byte[64];

    byte[][] actual = HashingUtils.splitIntoBlocks(input, 64);

    assertEquals(1, actual.length);
  }

  @Test
  void should_produce_two_blocks_on_128_byte_input() {
    byte[] input = new byte[128];

    byte[][] actual = HashingUtils.splitIntoBlocks(input, 64);

    assertEquals(2, actual.length);
  }

  @Test
  void should_produce_blocks_of_correct_size() {
    byte[] input = new byte[128];

    byte[][] actual = HashingUtils.splitIntoBlocks(input, 64);

    for (byte[] block : actual) {
      assertEquals(64, block.length);
    }
  }

  @Test
  void should_preserve_block_content_on_splitting() {
    byte[] input = new byte[64];
    input[0] = 0x01;
    input[63] = 0x02;

    byte[][] actual = HashingUtils.splitIntoBlocks(input, 64);

    assertEquals(0x01, actual[0][0]);
    assertEquals(0x02, actual[0][63]);
  }

  @Test
  void should_correctly_split_content_across_blocks() {
    byte[] input = new byte[128];
    input[64] = 0x42;

    byte[][] actual = HashingUtils.splitIntoBlocks(input, 64);

    assertEquals(0x42, actual[1][0]);
  }

  @Test
  void should_produce_correct_length_on_hex_string() {
    byte[] digest = new byte[16];

    assertEquals(32, HashingUtils.toHexString(digest).length());
  }

  @Test
  void should_produce_lowercase_hex_on_hex_string() {
    byte[] digest = new byte[] {(byte) 0xAB, (byte) 0xCD};

    assertEquals("abcd", HashingUtils.toHexString(digest));
  }

  @Test
  void should_produce_zero_actual_hex_on_small_byte_values() {
    byte[] digest = new byte[] {0x01, 0x0F};

    assertEquals("010f", HashingUtils.toHexString(digest));
  }

  @Test
  void should_produce_empty_string_on_empty_digest() {
    assertEquals("", HashingUtils.toHexString(new byte[0]));
  }

  @Test
  void should_produce_correct_byte_length_on_digest() {
    int[] state = new int[8];

    assertEquals(32, HashingUtils.toDigest(state, ByteOrder.BIG_ENDIAN).length);
  }

  @Test
  void should_write_big_endian_word_correctly_on_digest() {
    int[] state = {0x01020304, 0, 0, 0, 0, 0, 0, 0};

    byte[] actual = HashingUtils.toDigest(state, ByteOrder.BIG_ENDIAN);

    assertEquals((byte) 0x01, actual[0]);
    assertEquals((byte) 0x02, actual[1]);
    assertEquals((byte) 0x03, actual[2]);
    assertEquals((byte) 0x04, actual[3]);
  }

  @Test
  void should_write_little_endian_word_correctly_on_digest() {
    int[] state = {0x01020304, 0, 0, 0};

    byte[] actual = HashingUtils.toDigest(state, ByteOrder.LITTLE_ENDIAN);

    assertEquals((byte) 0x04, actual[0]);
    assertEquals((byte) 0x03, actual[1]);
    assertEquals((byte) 0x02, actual[2]);
    assertEquals((byte) 0x01, actual[3]);
  }

  @ParameterizedTest
  @MethodSource("provideStateAndByteOrder")
  void should_produce_correct_digest_length_on_arbitrary_state(int[] state, ByteOrder byteOrder) {
    byte[] actual = HashingUtils.toDigest(state, byteOrder);

    assertEquals(state.length * 4, actual.length);
  }
}
