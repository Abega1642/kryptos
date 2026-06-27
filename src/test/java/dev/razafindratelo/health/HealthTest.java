package dev.razafindratelo.health;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class HealthTest {

  @Test
  void health() {
    assertEquals("ok", Health.health());
  }
}
