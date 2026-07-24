package dev.razafindratelo.kryptos.hashing.bcrypt;

import static dev.razafindratelo.kryptos.encryption.symmetric.block_cypher.Blowfish.getInts;

import dev.razafindratelo.kryptos.encryption.symmetric.block_cypher.Blowfish;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class BcryptKeySchedule {

  private static final int P_SIZE = 18;
  private static final int S_BOX_COUNT = 4;
  private static final int S_BOX_SIZE = 256;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;

  private static final BcryptKeySchedule INSTANCE = new BcryptKeySchedule();

  public static BcryptKeySchedule getInstance() {
    return INSTANCE;
  }

  public int[] expandKey(int[] state, byte[] salt, byte[] key) {
    int[] p = extractP(state);
    int[][] s = extractS(state);

    xorKeyIntoP(p, key);

    SaltCursor saltCursor = new SaltCursor(salt);
    long[] block = {0L, 0L};

    for (int i = 0; i < P_SIZE; i += 2) {
      block = encryptNextBlock(block, saltCursor, p, s);
      p[i] = (int) block[0];
      p[i + 1] = (int) block[1];
    }

    for (int i = 0; i < S_BOX_COUNT; i++) {
      for (int j = 0; j < S_BOX_SIZE; j += 2) {
        block = encryptNextBlock(block, saltCursor, p, s);
        s[i][j] = (int) block[0];
        s[i][j + 1] = (int) block[1];
      }
    }

    return buildState(p, s);
  }

  private long[] encryptNextBlock(long[] previousBlock, SaltCursor saltCursor, int[] p, int[][] s) {
    long xL = saltCursor.nextWord();
    long xR = saltCursor.nextWord();
    return Blowfish.getInstance().encryptBlock(previousBlock[0] ^ xL, previousBlock[1] ^ xR, p, s);
  }

  private void xorKeyIntoP(int[] p, byte[] key) {
    int keyLen = key.length;
    int keyIndex = 0;
    for (int i = 0; i < P_SIZE; i++) {
      int data = 0;
      for (int j = 0; j < 4; j++) {
        data = (data << 8) | (key[keyIndex % keyLen] & UNSIGNED_BYTE_MASK);
        keyIndex++;
      }
      p[i] ^= data;
    }
  }

  public int[] eksBlowfishSetup(int cost, byte[] salt, byte[] password) {
    if (cost < 4 || cost > 31)
      throw new IllegalArgumentException(
          String.format("Cost must be between 4 and 31, got %d", cost));
    if (salt == null || salt.length != 16)
      throw new IllegalArgumentException("Salt must be exactly 16 bytes");
    if (password == null || password.length == 0)
      throw new IllegalArgumentException("Password must not be null or empty");

    int[] state = Blowfish.getInstance().initState();
    state = expandKey(state, salt, password);

    int rounds = 1 << cost;
    for (int i = 0; i < rounds; i++) {
      state = expandKey(state, new byte[16], password);
      state = expandKey(state, new byte[16], salt);
    }

    return state;
  }

  private int[] extractP(int[] state) {
    int[] p = new int[P_SIZE];
    System.arraycopy(state, 0, p, 0, P_SIZE);
    return p;
  }

  private int[][] extractS(int[] state) {
    int[][] s = new int[S_BOX_COUNT][S_BOX_SIZE];
    for (int i = 0; i < S_BOX_COUNT; i++) {
      System.arraycopy(state, P_SIZE + i * S_BOX_SIZE, s[i], 0, S_BOX_SIZE);
    }
    return s;
  }

  private int[] buildState(int[] p, int[][] s) {
    return getInts(p, s, P_SIZE, S_BOX_COUNT, S_BOX_SIZE);
  }
}
