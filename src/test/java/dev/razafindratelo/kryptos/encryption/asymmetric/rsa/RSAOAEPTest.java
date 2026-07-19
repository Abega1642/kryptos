package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class RSAOAEPTest {

  private static final RSAKeyGenerator generator = RSAKeyGenerator.getInstance();
  private static final RSAOAEP oaep = RSAOAEP.getInstance();

  private static RSAKeyPair KEY_PAIR_1024;
  private static RSAKeyPair KEY_PAIR_2048;

  @BeforeAll
  static void setUp() {
    KEY_PAIR_1024 = generator.generate(1024);
    KEY_PAIR_2048 = generator.generate(2048);
  }

  private byte[] randomMessage(int maxBytes) {
    return SecureRandom.getSeed(new SecureRandom().nextInt(maxBytes) + 1);
  }

  private RSAPublicKey toJdkPublicKey(
      dev.razafindratelo.kryptos.encryption.asymmetric.rsa.RSAPublicKey key) throws Exception {
    return (RSAPublicKey)
        KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(key.n(), key.e()));
  }

  private RSAPrivateKey toJdkPrivateKey(
      dev.razafindratelo.kryptos.encryption.asymmetric.rsa.RSAPrivateKey key) throws Exception {
    return (RSAPrivateKey)
        KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(key.n(), key.d()));
  }

  private Cipher jdkOAEPCipher(int mode, java.security.Key key) throws Exception {
    // PKCS#1 v2.2: OAEP with SHA-256 and MGF1-SHA256, empty label
    OAEPParameterSpec spec =
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    cipher.init(mode, key, spec);
    return cipher;
  }

  @Test
  void should_produce_correct_length_on_mgf1() {
    byte[] seed = SecureRandom.getSeed(32);
    byte[] actual = oaep.mgf1(seed, 100);
    assertEquals(100, actual.length);
  }

  @Test
  void should_produce_deterministic_output_on_mgf1() {
    byte[] seed = SecureRandom.getSeed(32);
    assertArrayEquals(oaep.mgf1(seed, 64), oaep.mgf1(seed, 64));
  }

  @Test
  void should_produce_different_output_on_different_seeds_mgf1() {
    assertFalse(
        Arrays.equals(
            oaep.mgf1(SecureRandom.getSeed(32), 64), oaep.mgf1(SecureRandom.getSeed(32), 64)));
  }

  @Test
  void should_throw_on_null_seed_mgf1() {
    assertThrows(IllegalArgumentException.class, () -> oaep.mgf1(null, 32));
  }

  @Test
  void should_throw_on_non_positive_length_mgf1() {
    assertThrows(IllegalArgumentException.class, () -> oaep.mgf1(SecureRandom.getSeed(32), 0));
  }

  @Test
  void should_return_zero_array_on_xor_with_itself() {
    byte[] input = SecureRandom.getSeed(32);
    byte[] actual = oaep.xor(input, input);
    assertArrayEquals(new byte[32], actual);
  }

  @Test
  void should_recover_original_on_double_xor() {
    byte[] a = SecureRandom.getSeed(32);
    byte[] b = SecureRandom.getSeed(32);
    byte[] actual = oaep.xor(oaep.xor(a, b), b);
    assertArrayEquals(a, actual);
  }

  @Test
  void should_produce_correct_length_on_pad() {
    int modulusBytes = 128;
    byte[] message = SecureRandom.getSeed(10);
    byte[] actual = oaep.pad(message, modulusBytes);
    assertEquals(modulusBytes, actual.length);
  }

  @Test
  void should_start_with_zero_byte_on_pad() {
    byte[] actual = oaep.pad(SecureRandom.getSeed(10), 128);
    assertEquals(0x00, actual[0]);
  }

  @Test
  void should_recover_message_on_pad_then_unpad() {
    byte[] message = SecureRandom.getSeed(20);
    byte[] padded = oaep.pad(message, 128);
    byte[] actual = oaep.unpad(padded, 128);
    assertArrayEquals(message, actual);
  }

  @Test
  void should_produce_different_padded_output_on_same_message() {
    // OAEP uses random seed -- same message produces different padded output
    byte[] message = SecureRandom.getSeed(20);
    assertFalse(Arrays.equals(oaep.pad(message, 128), oaep.pad(message, 128)));
  }

  @Test
  void should_throw_on_message_too_long_for_pad() {
    // max message = modulusBytes - 2*hLen - 2 = 128 - 64 - 2 = 62 bytes
    assertThrows(IllegalArgumentException.class, () -> oaep.pad(SecureRandom.getSeed(63), 128));
  }

  @Test
  void should_throw_on_null_message_pad() {
    assertThrows(IllegalArgumentException.class, () -> oaep.pad(null, 128));
  }

  @Test
  void should_throw_on_invalid_first_byte_unpad() {
    byte[] em = SecureRandom.getSeed(128);
    em[0] = 0x01;
    assertThrows(IllegalArgumentException.class, () -> oaep.unpad(em, 128));
  }

  @Test
  void should_throw_on_label_hash_mismatch_unpad() {
    byte[] em = oaep.pad(SecureRandom.getSeed(10), 128);
    // corrupt the label hash area (bytes 33-64 in DB)
    em[70] ^= (byte) 0xFF;
    assertThrows(IllegalArgumentException.class, () -> oaep.unpad(em, 128));
  }

  @Test
  void should_throw_on_null_message_encrypt() {
    assertThrows(
        IllegalArgumentException.class, () -> oaep.encrypt(null, KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_throw_on_null_public_key_encrypt() {
    assertThrows(
        IllegalArgumentException.class, () -> oaep.encrypt(SecureRandom.getSeed(10), null));
  }

  @Test
  void should_throw_on_null_ciphertext_decrypt() {
    assertThrows(
        IllegalArgumentException.class, () -> oaep.decrypt(null, KEY_PAIR_1024.privateKey()));
  }

  @Test
  void should_throw_on_null_private_key_decrypt() {
    assertThrows(
        IllegalArgumentException.class, () -> oaep.decrypt(SecureRandom.getSeed(128), null));
  }

  @RepeatedTest(10)
  void should_recover_plaintext_on_encrypt_then_decrypt_1024() {
    byte[] message = randomMessage(62);
    byte[] ciphertext = oaep.encrypt(message, KEY_PAIR_1024.publicKey());
    byte[] actual = oaep.decrypt(ciphertext, KEY_PAIR_1024.privateKey());
    assertArrayEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_recover_plaintext_on_encrypt_then_decrypt_2048() {
    byte[] message = randomMessage(190);
    byte[] ciphertext = oaep.encrypt(message, KEY_PAIR_2048.publicKey());
    byte[] actual = oaep.decrypt(ciphertext, KEY_PAIR_2048.privateKey());
    assertArrayEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_produce_different_ciphertext_on_same_message_1024() {
    // OAEP is non-deterministic -- fixes textbook RSA determinism weakness
    byte[] message = randomMessage(62);
    assertFalse(
        Arrays.equals(
            oaep.encrypt(message, KEY_PAIR_1024.publicKey()),
            oaep.encrypt(message, KEY_PAIR_1024.publicKey())));
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_1024() throws Exception {
    byte[] message = randomMessage(62);
    Cipher cipher = jdkOAEPCipher(Cipher.ENCRYPT_MODE, toJdkPublicKey(KEY_PAIR_1024.publicKey()));
    byte[] jdkCipher = cipher.doFinal(message);
    byte[] actual = oaep.decrypt(jdkCipher, KEY_PAIR_1024.privateKey());
    assertArrayEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_decrypt_jdk_ciphertext_on_2048() throws Exception {
    byte[] message = randomMessage(190);
    Cipher cipher = jdkOAEPCipher(Cipher.ENCRYPT_MODE, toJdkPublicKey(KEY_PAIR_2048.publicKey()));
    byte[] jdkCipher = cipher.doFinal(message);
    byte[] actual = oaep.decrypt(jdkCipher, KEY_PAIR_2048.privateKey());
    assertArrayEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_1024() throws Exception {
    byte[] message = randomMessage(62);
    byte[] ciphertext = oaep.encrypt(message, KEY_PAIR_1024.publicKey());
    Cipher cipher = jdkOAEPCipher(Cipher.DECRYPT_MODE, toJdkPrivateKey(KEY_PAIR_1024.privateKey()));
    byte[] actual = cipher.doFinal(ciphertext);
    assertArrayEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_produce_ciphertext_jdk_can_decrypt_on_2048() throws Exception {
    byte[] message = randomMessage(190);
    byte[] ciphertext = oaep.encrypt(message, KEY_PAIR_2048.publicKey());
    Cipher cipher = jdkOAEPCipher(Cipher.DECRYPT_MODE, toJdkPrivateKey(KEY_PAIR_2048.privateKey()));
    byte[] actual = cipher.doFinal(ciphertext);
    assertArrayEquals(message, actual);
  }
}
