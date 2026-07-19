package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HexFormat;
import javax.crypto.Cipher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class TextbookRSATest {

  private static final RSAKeyGenerator generator = RSAKeyGenerator.getInstance();
  private static final TextbookRSA textbookRSA = TextbookRSA.getInstance();

  private static RSAKeyPair KEY_PAIR_1024;
  private static RSAKeyPair KEY_PAIR_2048;

  @BeforeAll
  static void setUp() {
    KEY_PAIR_1024 = generator.generate(1_024);
    KEY_PAIR_2048 = generator.generate(2_048);
  }

  @Test
  void should_produce_correct_bit_length_on_1024_key_generation() {
    assertTrue(KEY_PAIR_1024.publicKey().n().bitLength() >= 1_000);
  }

  @Test
  void should_produce_correct_bit_length_on_2048_key_generation() {
    assertTrue(KEY_PAIR_2048.publicKey().n().bitLength() >= 2_000);
  }

  @Test
  void should_use_65537_as_public_exponent() {
    assertEquals(BigInteger.valueOf(65_537), KEY_PAIR_1024.publicKey().e());
    assertEquals(BigInteger.valueOf(65_537), KEY_PAIR_2048.publicKey().e());
  }

  @Test
  void should_produce_valid_d_on_key_generation() {
    // e * d ≡ 1 (mod phi(n)) -- verified by checking e * d mod phi = 1
    // We verify indirectly: encrypt then decrypt must recover original
    BigInteger message = BigInteger.valueOf(42);
    BigInteger cipher = textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey());
    assertEquals(message, textbookRSA.decrypt(cipher, KEY_PAIR_1024.privateKey()));
  }

  @Test
  void should_produce_distinct_key_pairs_on_each_generation() {
    RSAKeyPair pair1 = generator.generate(1_024);
    RSAKeyPair pair2 = generator.generate(1_024);
    assertNotEquals(pair1.publicKey().n(), pair2.publicKey().n());
  }

  @Test
  void should_throw_on_bit_length_less_than_512() {
    assertThrows(IllegalArgumentException.class, () -> generator.generate(256));
  }

  @Test
  void should_accept_valid_prime_candidate() {
    // 65537 is prime and gcd(65537, 65537-1) = 1
    assertTrue(generator.isValidPrime(BigInteger.valueOf(65_537)));
  }

  @Test
  void should_reject_prime_where_e_and_p_minus_1_are_not_coprime() {
    // p - 1 = 65537 * 2, so gcd(65537, p-1) = 65537 != 1
    // isValidPrime must return false regardless of primality
    BigInteger pMinusOne = BigInteger.valueOf(65_537).multiply(BigInteger.TWO);
    BigInteger p = pMinusOne.add(BigInteger.ONE);
    assertFalse(generator.isValidPrime(p));
  }

  @Test
  void should_throw_on_null_message_encrypt() {
    assertThrows(
        IllegalArgumentException.class, () -> textbookRSA.encrypt(null, KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_throw_on_null_public_key_encrypt() {
    assertThrows(IllegalArgumentException.class, () -> textbookRSA.encrypt(BigInteger.TWO, null));
  }

  @Test
  void should_throw_on_message_greater_than_n() {
    assertThrows(
        IllegalArgumentException.class,
        () -> textbookRSA.encrypt(KEY_PAIR_1024.publicKey().n(), KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_throw_on_negative_message_encrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> textbookRSA.encrypt(BigInteger.ONE.negate(), KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_throw_on_null_ciphertext_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> textbookRSA.decrypt(null, KEY_PAIR_1024.privateKey()));
  }

  @Test
  void should_throw_on_null_private_key_decrypt() {
    assertThrows(IllegalArgumentException.class, () -> textbookRSA.decrypt(BigInteger.TWO, null));
  }

  @Test
  void should_throw_on_negative_ciphertext_decrypt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> textbookRSA.decrypt(BigInteger.ONE.negate(), KEY_PAIR_1024.privateKey()));
  }

  @RepeatedTest(10)
  void should_recover_plaintext_on_encrypt_then_decrypt_1024() {
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_1024.publicKey().n());
    BigInteger ciphertext = textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey());
    BigInteger actual = textbookRSA.decrypt(ciphertext, KEY_PAIR_1024.privateKey());
    assertEquals(message, actual);
  }

  @RepeatedTest(10)
  void should_recover_plaintext_on_encrypt_then_decrypt_2048() {
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_2048.publicKey().n());
    BigInteger ciphertext = textbookRSA.encrypt(message, KEY_PAIR_2048.publicKey());
    BigInteger actual = textbookRSA.decrypt(ciphertext, KEY_PAIR_2048.privateKey());
    assertEquals(message, actual);
  }

  @Test
  void should_produce_different_ciphertext_on_different_messages() {
    BigInteger m1 = BigInteger.valueOf(42);
    BigInteger m2 = BigInteger.valueOf(43);
    assertNotEquals(
        textbookRSA.encrypt(m1, KEY_PAIR_1024.publicKey()),
        textbookRSA.encrypt(m2, KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_produce_same_ciphertext_on_same_message_and_key() {
    // textbook RSA is deterministic -- same message + key = same ciphertext
    // this is a weakness, not a feature
    BigInteger message = BigInteger.valueOf(42);
    assertEquals(
        textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey()),
        textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey()));
  }

  @RepeatedTest(10)
  void should_verify_signature_on_sign_then_verify() {
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_1024.privateKey().n());
    BigInteger signature = textbookRSA.sign(message, KEY_PAIR_1024.privateKey());
    assertTrue(textbookRSA.verify(message, signature, KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_reject_tampered_signature_on_verify() {
    BigInteger message = BigInteger.valueOf(42);
    BigInteger signature = textbookRSA.sign(message, KEY_PAIR_1024.privateKey());
    BigInteger tampered = signature.add(BigInteger.ONE);
    assertFalse(textbookRSA.verify(message, tampered, KEY_PAIR_1024.publicKey()));
  }

  @Test
  void should_reject_signature_from_different_key_on_verify() {
    RSAKeyPair other = generator.generate(1_024);
    BigInteger message = BigInteger.valueOf(42);
    BigInteger signature = textbookRSA.sign(message, KEY_PAIR_1024.privateKey());
    assertFalse(textbookRSA.verify(message, signature, other.publicKey()));
  }

  private java.security.interfaces.RSAPublicKey toJdkPublicKey(RSAPublicKey key) throws Exception {
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return (java.security.interfaces.RSAPublicKey)
        factory.generatePublic(new RSAPublicKeySpec(key.n(), key.e()));
  }

  private java.security.interfaces.RSAPrivateKey toJdkPrivateKey(RSAPrivateKey key)
      throws Exception {
    KeyFactory factory = KeyFactory.getInstance("RSA");
    return (java.security.interfaces.RSAPrivateKey)
        factory.generatePrivate(new RSAPrivateKeySpec(key.n(), key.d()));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_encrypt_1024() throws Exception {
    // textbook RSA = RSA/ECB/NoPadding in JDK
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_1024.publicKey().n());

    BigInteger actual = textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey());

    Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, toJdkPublicKey(KEY_PAIR_1024.publicKey()));
    BigInteger expected = new BigInteger(1, cipher.doFinal(message.toByteArray()));

    assertEquals(expected, actual);
  }

  @RepeatedTest(10)
  void should_match_jdk_on_decrypt_1024() throws Exception {
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_1024.publicKey().n());
    BigInteger ciphertext = textbookRSA.encrypt(message, KEY_PAIR_1024.publicKey());

    Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, toJdkPrivateKey(KEY_PAIR_1024.privateKey()));
    BigInteger expected = new BigInteger(1, cipher.doFinal(ciphertext.toByteArray()));

    assertEquals(expected, textbookRSA.decrypt(ciphertext, KEY_PAIR_1024.privateKey()));
  }

  @RepeatedTest(10)
  void should_match_jdk_on_sign_1024() throws Exception {
    BigInteger message =
        new BigInteger(HexFormat.of().formatHex(SecureRandom.getSeed(16)), 16)
            .mod(KEY_PAIR_1024.privateKey().n());
    BigInteger actual = textbookRSA.sign(message, KEY_PAIR_1024.privateKey());

    Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, toJdkPrivateKey(KEY_PAIR_1024.privateKey()));
    BigInteger expected = new BigInteger(1, cipher.doFinal(message.toByteArray()));

    assertEquals(expected, actual);
  }
}
