package dev.razafindratelo.kryptos.hashing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.razafindratelo.kryptos.encryption.symmetric.block_cypher.Blowfish;
import dev.razafindratelo.kryptos.hashing.bcrypt.BcryptKeySchedule;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class BcryptKeyScheduleTest {

  private final BcryptKeySchedule schedule = BcryptKeySchedule.getInstance();
  private final Blowfish blowfish =
      dev.razafindratelo.kryptos.encryption.symmetric.block_cypher.Blowfish.getInstance();

  private byte[] randomSalt() {
    return SecureRandom.getSeed(16);
  }

  private byte[] randomPassword() {
    return SecureRandom.getSeed(16);
  }

  @Test
  void should_throw_on_cost_less_than_4() {
    assertThrows(
        IllegalArgumentException.class,
        () -> schedule.eksBlowfishSetup(3, randomSalt(), randomPassword()));
  }

  @Test
  void should_throw_on_cost_greater_than_31() {
    assertThrows(
        IllegalArgumentException.class,
        () -> schedule.eksBlowfishSetup(32, randomSalt(), randomPassword()));
  }

  @Test
  void should_throw_on_null_salt() {
    assertThrows(
        IllegalArgumentException.class,
        () -> schedule.eksBlowfishSetup(10, null, randomPassword()));
  }

  @Test
  void should_throw_on_salt_not_16_bytes() {
    assertThrows(
        IllegalArgumentException.class,
        () -> schedule.eksBlowfishSetup(10, SecureRandom.getSeed(15), randomPassword()));
  }

  @Test
  void should_throw_on_null_password() {
    assertThrows(
        IllegalArgumentException.class, () -> schedule.eksBlowfishSetup(10, randomSalt(), null));
  }

  @Test
  void should_throw_on_empty_password() {
    assertThrows(
        IllegalArgumentException.class,
        () -> schedule.eksBlowfishSetup(10, randomSalt(), new byte[0]));
  }

  @Test
  void should_produce_correct_state_size() {
    int[] state = schedule.eksBlowfishSetup(4, randomSalt(), randomPassword());
    assertEquals(18 + 4 * 256, state.length);
  }

  @Test
  void should_produce_deterministic_state_on_same_inputs() {
    byte[] salt = randomSalt();
    byte[] password = randomPassword();
    int[] state1 = schedule.eksBlowfishSetup(4, salt, password);
    int[] state2 = schedule.eksBlowfishSetup(4, salt, password);
    assertArrayEquals(state1, state2);
  }

  @Test
  void should_produce_different_state_on_different_passwords() {
    byte[] salt = randomSalt();
    int[] s1 = schedule.eksBlowfishSetup(4, salt, randomPassword());
    int[] s2 = schedule.eksBlowfishSetup(4, salt, randomPassword());
    assertFalse(Arrays.equals(s1, s2));
  }

  @Test
  void should_produce_different_state_on_different_salts() {
    byte[] password = randomPassword();
    int[] s1 = schedule.eksBlowfishSetup(4, randomSalt(), password);
    int[] s2 = schedule.eksBlowfishSetup(4, randomSalt(), password);
    assertFalse(Arrays.equals(s1, s2));
  }

  @Test
  void should_produce_different_state_on_different_costs() {
    byte[] salt = randomSalt();
    byte[] password = randomPassword();
    int[] s1 = schedule.eksBlowfishSetup(4, salt, password);
    int[] s2 = schedule.eksBlowfishSetup(5, salt, password);
    assertFalse(Arrays.equals(s1, s2));
  }

  @Test
  void should_produce_different_state_from_plain_blowfish_init() {
    byte[] password = randomPassword();
    int[] bcryptState = schedule.eksBlowfishSetup(4, randomSalt(), password);
    int[] blowfishState = blowfish.initializeState(password);
    assertFalse(Arrays.equals(bcryptState, blowfishState));
  }

  @Test
  void should_produce_correct_state_size_on_expand_key() {
    int[] state = blowfish.initializeState(randomPassword());
    int[] result = schedule.expandKey(state, randomSalt(), randomPassword());
    assertEquals(18 + 4 * 256, result.length);
  }

  @Test
  void should_produce_different_state_on_expand_key() {
    byte[] password = randomPassword();
    int[] state = blowfish.initializeState(password);
    int[] expanded = schedule.expandKey(state, randomSalt(), password);
    assertFalse(Arrays.equals(state, expanded));
  }

  @Test
  void should_produce_deterministic_output_on_expand_key() {
    byte[] salt = randomSalt();
    byte[] password = randomPassword();
    int[] state = blowfish.initializeState(password);
    assertArrayEquals(
        schedule.expandKey(state.clone(), salt, password),
        schedule.expandKey(state.clone(), salt, password));
  }
}
