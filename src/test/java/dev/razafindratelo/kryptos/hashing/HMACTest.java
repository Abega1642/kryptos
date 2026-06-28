package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class HMACTest {

  private final SHA256 sha256 = SHA256.getInstance();
  private final MD5 md5 = MD5.getInstance();

  static Stream<Arguments> provideHmacSha256Vectors() {
    // RFC 4231 test vectors
    return Stream.of(
        Arguments.of(SecureRandom.getSeed(20), "Hi There".getBytes()),
        Arguments.of("Jefe".getBytes(), "what do ya want for nothing?".getBytes()),
        Arguments.of(SecureRandom.getSeed(20), SecureRandom.getSeed(50)));
  }

  static Stream<Arguments> provideHmacMd5Vectors() {
    // RFC 2202 test vectors
    return Stream.of(
        Arguments.of(SecureRandom.getSeed(16), "Hi There".getBytes()),
        Arguments.of("Jefe".getBytes(), "what do ya want for nothing?".getBytes()));
  }

  private byte[] jdkHmac(String algorithm, byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key, algorithm));
    return mac.doFinal(message);
  }

  @Test
  void should_produce_64_bytes_on_short_key() {
    byte[] key = "secret".getBytes();

    HMAC hmac = HMAC.of(sha256, key);
    byte[] actual = hmac.prepareKey(key);

    assertEquals(64, actual.length);
  }

  @Test
  void should_produce_64_bytes_on_key_longer_than_block_size() {
    byte[] key = new byte[100];

    HMAC hmac = HMAC.of(sha256, key);
    byte[] actual = hmac.prepareKey(key);

    assertEquals(64, actual.length);
  }

  @Test
  void should_zero_pad_short_key_to_block_size() {
    byte[] key = "abc".getBytes();

    HMAC hmac = HMAC.of(sha256, key);
    byte[] actual = hmac.prepareKey(key);

    for (int i = key.length; i < 64; i++) {
      assertEquals(0, actual[i]);
    }
  }

  @Test
  void should_hash_key_when_longer_than_block_size() {
    byte[] key = new byte[100];

    HMAC hmac = HMAC.of(sha256, key);
    byte[] actual = hmac.prepareKey(key);
    byte[] expectedHash = sha256.apply(key);

    for (int i = 0; i < expectedHash.length; i++) {
      assertEquals(expectedHash[i], actual[i]);
    }
  }

  @Test
  void should_produce_same_length_on_xor_with_pad() {
    byte[] key = new byte[64];
    HMAC hmac = HMAC.of(sha256, key);
    assertEquals(64, hmac.xorWithPad(key, (byte) 0x36).length);
  }

  @Test
  void should_xor_each_byte_with_pad() {
    byte[] key = new byte[] {0x00, 0x01, 0x02};

    HMAC hmac = HMAC.of(sha256, key);
    byte[] actual = hmac.xorWithPad(key, (byte) 0x36);

    assertEquals((byte) 0x36, actual[0]);
    assertEquals((byte) 0x37, actual[1]);
    assertEquals((byte) 0x34, actual[2]);
  }

  @Test
  void should_produce_different_results_for_ipad_and_opad() {
    byte[] key = "secret".getBytes();

    HMAC hmac = HMAC.of(sha256, key);
    byte[] prepared = hmac.prepareKey(key);
    byte[] innerKey = hmac.xorWithPad(prepared, (byte) 0x36);
    byte[] outerKey = hmac.xorWithPad(prepared, (byte) 0x5C);

    assertFalse(Arrays.equals(innerKey, outerKey));
  }

  @Test
  void should_produce_combined_length_on_concatenate() {
    HMAC hmac = HMAC.of(sha256, "key".getBytes());

    byte[] actual = hmac.concatenate(new byte[10], new byte[20]);

    assertEquals(30, actual.length);
  }

  @Test
  void should_preserve_content_on_concatenate() {
    HMAC hmac = HMAC.of(sha256, "key".getBytes());

    byte[] a = new byte[] {0x01, 0x02};
    byte[] b = new byte[] {0x03, 0x04};

    byte[] actual = hmac.concatenate(a, b);

    assertEquals(0x01, actual[0]);
    assertEquals(0x02, actual[1]);
    assertEquals(0x03, actual[2]);
    assertEquals(0x04, actual[3]);
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_message() {
    assertThrows(
        IllegalArgumentException.class, () -> HMAC.of(sha256, "key".getBytes()).apply(null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_null_key() {
    assertThrows(IllegalArgumentException.class, () -> HMAC.of(sha256, null));
  }

  @Test
  void should_throw_illegal_argument_exception_on_empty_key() {
    assertThrows(IllegalArgumentException.class, () -> HMAC.of(sha256, new byte[0]));
  }

  @Test
  void should_produce_32_bytes_on_hmac_sha256() {
    byte[] actual = HMAC.of(sha256, "key".getBytes()).apply("message".getBytes());

    assertEquals(32, actual.length);
  }

  @Test
  void should_produce_16_bytes_on_hmac_md5() {
    byte[] actual = HMAC.of(md5, "key".getBytes()).apply("message".getBytes());

    assertEquals(16, actual.length);
  }

  @Test
  void should_produce_same_tag_on_same_key_and_message() {
    byte[] key = "secret".getBytes();
    byte[] message = "message".getBytes();

    HMAC hmac = HMAC.of(sha256, key);

    assertArrayEquals(hmac.apply(message), hmac.apply(message));
  }

  @Test
  void should_produce_different_tags_on_different_messages() {
    byte[] key = "secret".getBytes();

    HMAC hmac = HMAC.of(sha256, key);

    assertFalse(
        Arrays.equals(hmac.apply("message1".getBytes()), hmac.apply("message2".getBytes())));
  }

  @Test
  void should_produce_different_tags_on_different_keys() {
    byte[] message = "message".getBytes();

    assertFalse(
        Arrays.equals(
            HMAC.of(sha256, "key1".getBytes()).apply(message),
            HMAC.of(sha256, "key2".getBytes()).apply(message)));
  }

  @ParameterizedTest
  @MethodSource("provideHmacSha256Vectors")
  void should_match_jdk_hmac_sha256_on_known_vectors(byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] actual = HMAC.of(sha256, key).apply(message);
    byte[] expected = jdkHmac("HmacSHA256", key, message);

    assertArrayEquals(expected, actual);
  }

  @ParameterizedTest
  @MethodSource("provideHmacMd5Vectors")
  void should_match_jdk_hmac_md5_on_known_vectors(byte[] key, byte[] message)
      throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] actual = HMAC.of(md5, key).apply(message);
    byte[] expected = jdkHmac("HmacMD5", key, message);

    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_hmac_sha256_on_random_input()
      throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] key = SecureRandom.getSeed(32);
    byte[] message = SecureRandom.getSeed(64);

    byte[] actual = HMAC.of(sha256, key).apply(message);
    byte[] expected = jdkHmac("HmacSHA256", key, message);

    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_hmac_md5_on_random_input()
      throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] key = SecureRandom.getSeed(32);
    byte[] message = SecureRandom.getSeed(64);

    byte[] actual = HMAC.of(md5, key).apply(message);
    byte[] expected = jdkHmac("HmacMD5", key, message);

    assertArrayEquals(expected, actual);
  }
}
