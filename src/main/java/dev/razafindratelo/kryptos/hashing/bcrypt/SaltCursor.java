package dev.razafindratelo.kryptos.hashing.bcrypt;

import static dev.razafindratelo.kryptos.hashing.HashingUtils.UNSIGNED_BYTE_MASK;

public final class SaltCursor {
  private final byte[] salt;
  private final int length;
  private int position;

  public SaltCursor(byte[] salt) {
    this.salt = salt;
    this.length = salt.length;
  }

  public long nextWord() {
    long word = 0;
    for (int i = 0; i < 4; i++) {
      word = (word << 8) | (salt[position % length] & UNSIGNED_BYTE_MASK);
      position++;
    }
    return word;
  }
}
