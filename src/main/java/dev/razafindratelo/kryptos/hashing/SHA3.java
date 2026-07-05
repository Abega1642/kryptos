package dev.razafindratelo.kryptos.hashing;

import java.util.function.Function;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SHA3 implements Function<byte[], byte[]> {

  private static final int STATE_SIZE = 25;
  private static final int LANE_SIZE_BITS = 64;
  private static final int ROUNDS = 24;
  private static final int RATE_BYTES = 136;
  private static final int OUTPUT_BYTES = 32;
  private static final int DOMAIN_SUFFIX = 0x06;
  private static final int PADDING_END = 0x80;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;

  private static final long[] ROUND_CONSTANTS = {
    0x0000000000000001L, 0x0000000000008082L,
    0x800000000000808aL, 0x8000000080008000L,
    0x000000000000808bL, 0x0000000080000001L,
    0x8000000080008081L, 0x8000000000008009L,
    0x000000000000008aL, 0x0000000000000088L,
    0x0000000080008009L, 0x000000008000000aL,
    0x000000008000808bL, 0x800000000000008bL,
    0x8000000000008089L, 0x8000000000008003L,
    0x8000000000008002L, 0x8000000000000080L,
    0x000000000000800aL, 0x800000008000000aL,
    0x8000000080008081L, 0x8000000000008080L,
    0x0000000080000001L, 0x8000000080008008L
  };

  private static final int[][] RHO_OFFSETS = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14}
  };

  private static final SHA3 INSTANCE = new SHA3();

  public static SHA3 getInstance() {
    return INSTANCE;
  }

  @Override
  public byte[] apply(byte[] input) {
    if (input == null) throw new IllegalArgumentException("Input must not be null");

    byte[] padded = pad(input);
    long[] state = absorb(padded);
    return squeeze(state);
  }

  public byte[] pad(byte[] input) {
    int blockCount = (input.length / RATE_BYTES) + 1;
    int paddedLength = blockCount * RATE_BYTES;
    byte[] padded = new byte[paddedLength];

    System.arraycopy(input, 0, padded, 0, input.length);
    padded[input.length] = (byte) DOMAIN_SUFFIX;
    padded[paddedLength - 1] ^= (byte) PADDING_END;

    return padded;
  }

  public long[] toState(byte[] block, long[] state) {
    for (int i = 0; i < RATE_BYTES / 8; i++) {
      long lane = 0;
      for (int j = 0; j < 8; j++) {
        lane |= ((long) (block[i * 8 + j] & UNSIGNED_BYTE_MASK)) << (j * 8);
      }
      state[i] ^= lane;
    }
    return state;
  }

  public long rotateLeft(long value, int shift) {
    return (value << shift) | (value >>> (LANE_SIZE_BITS - shift));
  }

  public long[] theta(long[] state) {
    long[] result = new long[STATE_SIZE];
    long[] c = new long[5];
    long[] d = new long[5];

    for (int x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (int x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotateLeft(c[(x + 1) % 5], 1);
    }
    System.arraycopy(state, 0, result, 0, STATE_SIZE);
    for (int x = 0; x < 5; x++) {
      for (int y = 0; y < 5; y++) {
        result[x + y * 5] ^= d[x];
      }
    }
    return result;
  }

  public long[] rhoPi(long[] state) {
    long[] result = new long[STATE_SIZE];
    for (int x = 0; x < 5; x++) {
      for (int y = 0; y < 5; y++) {
        result[y + ((2 * x + 3 * y) % 5) * 5] = rotateLeft(state[x + y * 5], RHO_OFFSETS[x][y]);
      }
    }
    return result;
  }

  public long[] chi(long[] state) {
    long[] result = new long[STATE_SIZE];
    for (int y = 0; y < 5; y++) {
      for (int x = 0; x < 5; x++) {
        result[x + y * 5] =
            state[x + y * 5] ^ ((~state[(x + 1) % 5 + y * 5]) & state[(x + 2) % 5 + y * 5]);
      }
    }
    return result;
  }

  public long[] iota(long[] state, int round) {
    long[] result = state.clone();
    result[0] ^= ROUND_CONSTANTS[round];
    return result;
  }

  public long[] keccakF(long[] state) {
    long[] result = state.clone();
    for (int round = 0; round < ROUNDS; round++) {
      result = theta(result);
      result = rhoPi(result);
      result = chi(result);
      result = iota(result, round);
    }
    return result;
  }

  public long[] absorb(byte[] padded) {
    long[] state = new long[STATE_SIZE];
    byte[] block = new byte[RATE_BYTES];

    for (int offset = 0; offset < padded.length; offset += RATE_BYTES) {
      System.arraycopy(padded, offset, block, 0, RATE_BYTES);
      state = keccakF(toState(block, state));
    }

    return state;
  }

  public byte[] squeeze(long[] state) {
    byte[] digest = new byte[OUTPUT_BYTES];
    int index = 0;

    for (int i = 0; i < OUTPUT_BYTES / 8; i++) {
      long lane = state[i];
      for (int j = 0; j < 8; j++) {
        digest[index++] = (byte) (lane >>> (j * 8));
      }
    }

    return digest;
  }

  public String toHexString(byte[] digest) {
    return HashingUtils.toHexString(digest);
  }
}
