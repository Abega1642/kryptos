package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class BlowfishTest {

  private final Blowfish blowfish = Blowfish.getInstance();

  private byte[] randomKey() {
    return SecureRandom.getSeed(16);
  }

  private byte[] randomBlock() {
    return SecureRandom.getSeed(8);
  }

  private int[] p() {
    return blowfish.initializeState("testkey".getBytes()).clone();
  }

  private int[][] s() {
    int[] state = blowfish.initializeState("testkey".getBytes());
    int[][] s = new int[4][256];
    for (int i = 0; i < 4; i++) {
      System.arraycopy(state, 18 + i * 256, s[i], 0, 256);
    }
    return s;
  }

  @Test
  void should_throw_on_null_key() {
    assertThrows(IllegalArgumentException.class, () -> blowfish.initializeState(null));
  }

  @Test
  void should_throw_on_empty_key() {
    assertThrows(IllegalArgumentException.class, () -> blowfish.initializeState(new byte[0]));
  }

  @Test
  void should_throw_on_key_longer_than_56_bytes() {
    assertThrows(
        IllegalArgumentException.class, () -> blowfish.initializeState(SecureRandom.getSeed(57)));
  }

  @Test
  void should_produce_correct_state_size_on_initialization() {
    int[] state = blowfish.initializeState("key".getBytes());
    assertEquals(18 + 4 * 256, state.length);
  }

  @Test
  void should_produce_different_state_on_different_keys() {
    int[] state1 = blowfish.initializeState("key1".getBytes());
    int[] state2 = blowfish.initializeState("key2".getBytes());
    assertFalse(Arrays.equals(state1, state2));
  }

  @Test
  void should_produce_same_state_on_same_key() {
    byte[] key = randomKey();
    int[] state1 = blowfish.initializeState(key);
    int[] state2 = blowfish.initializeState(key);
    assertArrayEquals(state1, state2);
  }

  @Test
  void should_produce_different_state_from_init_constants() {
    int[] state = blowfish.initializeState("key".getBytes());
    // P[0] after key schedule must differ from P_INIT[0]
    assertNotEquals(0x243f6a88, state[0]);
  }

  @Test
  void should_produce_non_zero_on_non_zero_input() {
    assertNotEquals(0, blowfish.fFunction(0x12345678, p(), s()));
  }

  @Test
  void should_produce_deterministic_output_on_f_function() {
    int[] p = p();
    int[][] s = s();

    var actual = blowfish.fFunction(0x12345678, p, s);

    assertEquals(actual, blowfish.fFunction(0x12345678, p, s));
  }

  @Test
  void should_produce_two_longs_on_encrypt_block() {
    long[] result = blowfish.encryptBlock(0L, 0L, p(), s());
    assertEquals(2, result.length);
  }

  @Test
  void should_recover_original_on_encrypt_then_decrypt() {
    int[] p = p();
    int[][] s = s();
    long xL = 0x12345678L;
    long xR = 0x9ABCDEF0L;
    long[] cipher = blowfish.encryptBlock(xL, xR, p, s);
    long[] actual = blowfish.decryptBlock(cipher[0], cipher[1], p, s);
    assertEquals(xL, actual[0]);
    assertEquals(xR, actual[1]);
  }

  @Test
  void should_produce_different_output_on_different_inputs() {
    int[] p = p();
    int[][] s = s();
    long[] c1 = blowfish.encryptBlock(0x12345678L, 0x9ABCDEF0L, p, s);
    long[] c2 = blowfish.encryptBlock(0xFEDCBA98L, 0x76543210L, p, s);
    assertFalse(Arrays.equals(c1, c2));
  }

  @Test
  void should_throw_on_null_block() {
    assertThrows(IllegalArgumentException.class, () -> blowfish.apply(null, randomKey()));
  }

  @Test
  void should_throw_on_null_key_apply() {
    assertThrows(IllegalArgumentException.class, () -> blowfish.apply(randomBlock(), null));
  }

  @Test
  void should_throw_on_wrong_block_size() {
    assertThrows(
        IllegalArgumentException.class, () -> blowfish.apply(SecureRandom.getSeed(7), randomKey()));
  }

  @RepeatedTest(10)
  void should_match_bouncy_castle_on_random_input() {
    byte[] block = randomBlock();
    byte[] key = randomKey();

    byte[] actual = blowfish.apply(block, key);

    org.bouncycastle.crypto.engines.BlowfishEngine engine =
        new org.bouncycastle.crypto.engines.BlowfishEngine();
    engine.init(true, new org.bouncycastle.crypto.params.KeyParameter(key));
    byte[] expected = new byte[8];
    engine.processBlock(block, 0, expected, 0);

    assertArrayEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_recover_original_on_encrypt_then_decrypt_apply() {
    byte[] block = randomBlock();
    byte[] key = randomKey();
    byte[] encrypted = blowfish.apply(block, key);

    // decrypt using Bouncy Castle
    org.bouncycastle.crypto.engines.BlowfishEngine engine =
        new org.bouncycastle.crypto.engines.BlowfishEngine();
    engine.init(false, new org.bouncycastle.crypto.params.KeyParameter(key));
    byte[] actual = new byte[8];
    engine.processBlock(encrypted, 0, actual, 0);

    assertArrayEquals(block, actual);
  }

  @Test
  void should_match_known_vector() {
    // Blowfish known answer test from Bruce Schneier's test vectors
    byte[] key = HexFormat.of().parseHex("0000000000000000");
    byte[] block = HexFormat.of().parseHex("0000000000000000");
    byte[] expected = HexFormat.of().parseHex("4ef997456198dd78");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @Test
  void should_match_known_vector_1() {
    byte[] key = HexFormat.of().parseHex("ffffffffffffffff");
    byte[] block = HexFormat.of().parseHex("ffffffffffffffff");
    byte[] expected = HexFormat.of().parseHex("51866fd5b85ecb8a");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @Test
  void should_match_known_vector_2() {
    byte[] key = HexFormat.of().parseHex("3000000000000000");
    byte[] block = HexFormat.of().parseHex("1000000000000001");
    byte[] expected = HexFormat.of().parseHex("7d856f9a613063f2");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @Test
  void should_match_known_vector_3() {
    byte[] key = HexFormat.of().parseHex("1111111111111111");
    byte[] block = HexFormat.of().parseHex("1111111111111111");
    byte[] expected = HexFormat.of().parseHex("2466dd878b963c9d");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @Test
  void should_match_known_vector_4() {
    byte[] key = HexFormat.of().parseHex("0123456789abcdef");
    byte[] block = HexFormat.of().parseHex("1111111111111111");
    byte[] expected = HexFormat.of().parseHex("61f9c3802281b096");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @Test
  void should_match_known_vector_5() {
    byte[] key = HexFormat.of().parseHex("fedcba9876543210");
    byte[] block = HexFormat.of().parseHex("0123456789abcdef");
    byte[] expected = HexFormat.of().parseHex("0aceab0fc6a0a28d");
    assertArrayEquals(expected, blowfish.apply(block, key));
  }

  @RepeatedTest(10)
  void should_produce_different_ciphertext_on_different_keys() {
    byte[] block = randomBlock();
    assertFalse(
        Arrays.equals(blowfish.apply(block, randomKey()), blowfish.apply(block, randomKey())));
  }

  @Test
  void should_produce_8_bytes_on_apply() {
    assertEquals(8, blowfish.apply(randomBlock(), randomKey()).length);
  }
}
