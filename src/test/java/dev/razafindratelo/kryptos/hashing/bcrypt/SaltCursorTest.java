package dev.razafindratelo.kryptos.hashing.bcrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.SecureRandom;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class SaltCursorTest {

  private static final int UNSIGNED_BYTE_MASK = 0xFF;

  private long bigEndianWord(byte[] bytes, int offset) {
    long word = 0;
    for (int i = 0; i < 4; i++) {
      word = (word << 8) | (bytes[offset + i] & UNSIGNED_BYTE_MASK);
    }
    return word;
  }

  @Test
  void should_return_big_endian_word_on_first_call() {
    byte[] salt = SecureRandom.getSeed(4);
    SaltCursor cursor = new SaltCursor(salt);

    assertEquals(bigEndianWord(salt, 0), cursor.nextWord());
  }

  @RepeatedTest(10)
  void should_read_sequential_words_on_repeated_calls_within_bounds() {
    byte[] salt = SecureRandom.getSeed(16);
    SaltCursor cursor = new SaltCursor(salt);

    assertEquals(bigEndianWord(salt, 0), cursor.nextWord());
    assertEquals(bigEndianWord(salt, 4), cursor.nextWord());
    assertEquals(bigEndianWord(salt, 8), cursor.nextWord());
    assertEquals(bigEndianWord(salt, 12), cursor.nextWord());
  }

  @Test
  void should_wrap_cyclically_on_salt_shorter_than_four_bytes() {
    byte[] salt = SecureRandom.getSeed(2);
    SaltCursor cursor = new SaltCursor(salt);

    byte[] expandedWindow = {salt[0], salt[1], salt[0], salt[1]};
    assertEquals(bigEndianWord(expandedWindow, 0), cursor.nextWord());
  }

  @Test
  void should_wrap_to_start_after_consuming_full_salt_length() {
    byte[] salt = SecureRandom.getSeed(16);
    SaltCursor cursor = new SaltCursor(salt);

    for (int i = 0; i < 4; i++) {
      cursor.nextWord();
    }

    assertEquals(bigEndianWord(salt, 0), cursor.nextWord());
  }

  @Test
  void should_advance_position_by_four_bytes_per_call_on_one_byte_salt() {
    byte[] salt = SecureRandom.getSeed(1);
    SaltCursor cursor = new SaltCursor(salt);

    long firstWord = cursor.nextWord();
    long secondWord = cursor.nextWord();

    long allSameByteWord = bigEndianWord(new byte[] {salt[0], salt[0], salt[0], salt[0]}, 0);
    assertEquals(allSameByteWord, firstWord);
    assertEquals(allSameByteWord, secondWord);
  }
}
