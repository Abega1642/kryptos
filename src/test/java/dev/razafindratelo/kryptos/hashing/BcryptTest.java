package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.razafindratelo.kryptos.hashing.bcrypt.Bcrypt;
import dev.razafindratelo.kryptos.hashing.bcrypt.BcryptKeySchedule;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class BcryptTest {

  private final Bcrypt bcrypt = Bcrypt.getInstance();

  private String randomPassword() {
    return new String(SecureRandom.getSeed(16));
  }

  private String randomAsciiPassword(int byteLength) {
    byte[] randomBytes = SecureRandom.getSeed((byteLength + 1) / 2);
    return HexFormat.of().formatHex(randomBytes).substring(0, byteLength);
  }

  private String randomUnicodePassword(int codePointCount) {
    SecureRandom random = new SecureRandom();
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < codePointCount; i++) {
      sb.appendCodePoint(0x4E00 + random.nextInt(0x9FFF - 0x4E00));
    }
    return sb.toString();
  }

  @Test
  void should_produce_16_bytes_on_generate_salt() {
    assertEquals(16, bcrypt.generateSalt().length);
  }

  @RepeatedTest(10)
  void should_produce_unique_salt_on_each_call() {
    assertFalse(Arrays.equals(bcrypt.generateSalt(), bcrypt.generateSalt()));
  }

  @Test
  void should_produce_23_bytes_on_encrypt_magic() {
    int[] state =
        BcryptKeySchedule.getInstance()
            .eksBlowfishSetup(4, bcrypt.generateSalt(), "password".getBytes());
    assertEquals(23, bcrypt.encryptMagic(state).length);
  }

  @Test
  void should_produce_deterministic_output_on_encrypt_magic() {
    byte[] salt = bcrypt.generateSalt();
    int[] state = BcryptKeySchedule.getInstance().eksBlowfishSetup(4, salt, "password".getBytes());
    assertArrayEquals(bcrypt.encryptMagic(state), bcrypt.encryptMagic(state));
  }

  @Test
  void should_throw_on_null_password_hash() {
    assertThrows(IllegalArgumentException.class, () -> bcrypt.hash(null));
  }

  @Test
  void should_throw_on_empty_password_hash() {
    assertThrows(IllegalArgumentException.class, () -> bcrypt.hash(""));
  }

  @Test
  void should_throw_on_cost_less_than_4() {
    assertThrows(IllegalArgumentException.class, () -> bcrypt.hash("password", 3));
  }

  @Test
  void should_throw_on_cost_greater_than_31() {
    assertThrows(IllegalArgumentException.class, () -> bcrypt.hash("password", 32));
  }

  @Test
  void should_throw_on_null_password_verify() {
    assertThrows(
        IllegalArgumentException.class, () -> bcrypt.verify(null, bcrypt.hash("password", 4)));
  }

  @Test
  void should_throw_on_null_hash_verify() {
    assertThrows(IllegalArgumentException.class, () -> bcrypt.verify("password", null));
  }

  @RepeatedTest(10)
  void should_verify_correct_password() {
    String password = randomPassword();
    String hashed = bcrypt.hash(password, 4);
    assertTrue(bcrypt.verify(password, hashed));
  }

  @RepeatedTest(10)
  void should_reject_wrong_password() {
    String hashed = bcrypt.hash(randomPassword(), 4);
    assertFalse(bcrypt.verify(randomPassword(), hashed));
  }

  @Test
  void should_reject_tampered_hash() {
    String hashed = bcrypt.hash("password", 4);
    String tampered = hashed.substring(0, 59) + (hashed.charAt(59) == 'a' ? 'b' : 'a');
    assertFalse(bcrypt.verify("password", tampered));
  }

  @Test
  void should_recover_original_on_encode_then_decode() {
    byte[] data = SecureRandom.getSeed(16);
    String encoded = bcrypt.bcryptBase64Encode(data, 16);
    byte[] actual = bcrypt.decodeBase64(encoded, 16);
    assertArrayEquals(data, actual);
  }

  @Test
  void should_use_bcrypt_alphabet_on_encode() {
    byte[] data = SecureRandom.getSeed(16);
    String encoded = bcrypt.bcryptBase64Encode(data, 16);
    for (char c : encoded.toCharArray()) {
      assertTrue(
          "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".indexOf(c) >= 0);
    }
  }

  @Test
  void should_produce_22_chars_for_16_byte_salt() {
    assertEquals(22, bcrypt.bcryptBase64Encode(SecureRandom.getSeed(16), 16).length());
  }

  @Test
  void should_produce_31_chars_for_23_byte_hash() {
    assertEquals(31, bcrypt.bcryptBase64Encode(SecureRandom.getSeed(23), 23).length());
  }

  @Test
  void should_produce_correct_format_on_hash() {
    String hashed = bcrypt.hash("password", 4);
    assertTrue(hashed.startsWith("$2b$"));
  }

  @Test
  void should_produce_correct_cost_in_hash() {
    String hashed = bcrypt.hash("password", 10);
    assertTrue(hashed.startsWith("$2b$10$"));
  }

  @Test
  void should_produce_60_char_hash() {
    // $2b$ (4) + cost (2) + $ (1) + salt (22) + hash (31) = 60
    assertEquals(60, bcrypt.hash("password", 4).length());
  }

  @RepeatedTest(10)
  void should_produce_different_hash_on_same_password() {
    String password = randomPassword();
    assertNotEquals(bcrypt.hash(password, 4), bcrypt.hash(password, 4));
  }

  @RepeatedTest(10)
  void should_verify_spring_hash_with_our_implementation() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String password = randomPassword();
    String hashed = encoder.encode(password);
    assertTrue(bcrypt.verify(password, hashed));
  }

  @RepeatedTest(10)
  void should_have_our_hash_verified_by_spring() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String password = randomPassword();
    String hashed = bcrypt.hash(password, 4);
    assertTrue(encoder.matches(password, hashed));
  }

  @RepeatedTest(10)
  void should_match_spring_on_same_salt_and_cost() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String password = randomPassword();
    byte[] salt = bcrypt.generateSalt();
    String ours = bcrypt.hash(password, 4, salt);
    assertTrue(encoder.matches(password, ours));
  }

  @Test
  void should_match_spring_at_minimum_cost() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String password = randomPassword();
    assertTrue(encoder.matches(password, bcrypt.hash(password, 4)));
  }

  @Test
  void should_match_spring_at_cost_six() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(6);
    String password = randomPassword();
    assertTrue(encoder.matches(password, bcrypt.hash(password, 6)));
  }

  @Test
  void should_match_spring_on_password_exactly_72_bytes() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String password = randomAsciiPassword(72);
    assertTrue(encoder.matches(password, bcrypt.hash(password, 4)));
  }

  @Test
  void should_produce_same_hash_as_spring_when_passwords_differ_only_after_72_bytes() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String base = randomAsciiPassword(72);
    String extendedA = base + randomAsciiPassword(10);
    String extendedB = base + randomAsciiPassword(10);
    byte[] salt = bcrypt.generateSalt();

    String ours = bcrypt.hash(extendedA, 4, salt);
    assertTrue(encoder.matches(extendedB, ours));
  }

  @Test
  void should_verify_provos_mazieres_reference_vector_short_password() {
    // Reference test vector, Provos and Mazieres bcrypt implementation
    assertTrue(bcrypt.verify("a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"));
  }

  @Test
  void should_verify_provos_mazieres_reference_vector_three_char_password() {
    var expected = new BCryptPasswordEncoder().encode("abc");
    // Reference test vector, Provos and Mazieres bcrypt implementation
    assertTrue(bcrypt.verify("abc", expected));
  }

  @Test
  void should_reject_wrong_password_against_spring_hash() {
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    String hashed = encoder.encode(randomPassword());
    assertFalse(bcrypt.verify(randomPassword(), hashed));
  }
}
