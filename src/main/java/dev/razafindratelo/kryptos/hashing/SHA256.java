package dev.razafindratelo.kryptos.hashing;

import static dev.razafindratelo.kryptos.hashing.HashingUtils.BLOCK_SIZE_BYTES;
import static dev.razafindratelo.kryptos.hashing.HashingUtils.INITIAL_SCHEDULE_SIZE;
import static dev.razafindratelo.kryptos.hashing.HashingUtils.WORD_SIZE_BITS;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.Function;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SHA256 implements Function<byte[], byte[]> {

  public static final int[] K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  private static final int[] INIT_STATE = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };
  private static final int MESSAGE_SCHEDULE_SIZE = 64;
  private static final int SIGMA0_ROTATION_1 = 2;
  private static final int SIGMA0_ROTATION_2 = 13;
  private static final int SIGMA0_ROTATION_3 = 22;
  private static final int SIGMA1_ROTATION_1 = 6;
  private static final int SIGMA1_ROTATION_2 = 11;
  private static final int SIGMA1_ROTATION_3 = 25;
  private static final int LITTLE_SIGMA0_ROTATION_1 = 7;
  private static final int LITTLE_SIGMA0_ROTATION_2 = 18;
  private static final int LITTLE_SIGMA0_SHIFT = 3;
  private static final int LITTLE_SIGMA1_ROTATION_1 = 17;
  private static final int LITTLE_SIGMA1_ROTATION_2 = 19;
  private static final int LITTLE_SIGMA1_SHIFT = 10;
  private static final int SCHEDULE_WORD_OFFSET_2 = 2;
  private static final int SCHEDULE_WORD_OFFSET_7 = 7;
  private static final int SCHEDULE_WORD_OFFSET_15 = 15;
  private static final int SCHEDULE_WORD_OFFSET_16 = 16;

  private static final SHA256 INSTANCE = new SHA256();

  public static SHA256 getInstance() {
    return INSTANCE;
  }

  @Override
  public byte[] apply(byte[] input) {
    if (input == null) throw new IllegalArgumentException("Input must not be null");

    byte[] padded = pad(input);
    int[] state = INIT_STATE.clone();

    for (byte[] block : HashingUtils.splitIntoBlocks(padded, BLOCK_SIZE_BYTES)) {
      state = compressBlock(state, buildMessageSchedule(block));
    }

    return toDigest(state);
  }

  public byte[] pad(byte[] input) {
    return HashingUtils.pad(input, ByteOrder.BIG_ENDIAN);
  }

  public int rightRotate(int value, int shift) {
    return (value >>> shift) | (value << (WORD_SIZE_BITS - shift));
  }

  public int ch(int e, int f, int g) {
    return (e & f) ^ (~e & g);
  }

  public int maj(int a, int b, int c) {
    return (a & b) ^ (a & c) ^ (b & c);
  }

  public int sigma0(int a) {
    return rightRotate(a, SIGMA0_ROTATION_1)
        ^ rightRotate(a, SIGMA0_ROTATION_2)
        ^ rightRotate(a, SIGMA0_ROTATION_3);
  }

  public int sigma1(int e) {
    return rightRotate(e, SIGMA1_ROTATION_1)
        ^ rightRotate(e, SIGMA1_ROTATION_2)
        ^ rightRotate(e, SIGMA1_ROTATION_3);
  }

  public int littleSigma0(int x) {
    return rightRotate(x, LITTLE_SIGMA0_ROTATION_1)
        ^ rightRotate(x, LITTLE_SIGMA0_ROTATION_2)
        ^ (x >>> LITTLE_SIGMA0_SHIFT);
  }

  public int littleSigma1(int x) {
    return rightRotate(x, LITTLE_SIGMA1_ROTATION_1)
        ^ rightRotate(x, LITTLE_SIGMA1_ROTATION_2)
        ^ (x >>> LITTLE_SIGMA1_SHIFT);
  }

  public int[] buildMessageSchedule(byte[] block) {
    int[] w = loadMessageWords(block);
    return expandMessageSchedule(w);
  }

  private int[] loadMessageWords(byte[] block) {
    int[] w = new int[MESSAGE_SCHEDULE_SIZE];
    ByteBuffer buffer = ByteBuffer.wrap(block).order(ByteOrder.BIG_ENDIAN);
    for (int i = 0; i < INITIAL_SCHEDULE_SIZE; i++) {
      w[i] = buffer.getInt();
    }
    return w;
  }

  private int[] expandMessageSchedule(int[] w) {
    for (int i = INITIAL_SCHEDULE_SIZE; i < MESSAGE_SCHEDULE_SIZE; i++) {
      w[i] =
          littleSigma1(w[i - SCHEDULE_WORD_OFFSET_2])
              + w[i - SCHEDULE_WORD_OFFSET_7]
              + littleSigma0(w[i - SCHEDULE_WORD_OFFSET_15])
              + w[i - SCHEDULE_WORD_OFFSET_16];
    }
    return w;
  }

  public int[] compressBlock(int[] state, int[] w) {
    int a = state[0];
    int b = state[1];
    int c = state[2];
    int d = state[3];
    int e = state[4];
    int f = state[5];
    int g = state[6];
    int h = state[7];

    for (int i = 0; i < MESSAGE_SCHEDULE_SIZE; i++) {
      int temp1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
      int temp2 = sigma0(a) + maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    return new int[] {
      state[0] + a,
      state[1] + b,
      state[2] + c,
      state[3] + d,
      state[4] + e,
      state[5] + f,
      state[6] + g,
      state[7] + h
    };
  }

  public byte[] toDigest(int[] state) {
    return HashingUtils.toDigest(state, ByteOrder.BIG_ENDIAN);
  }

  public String toHexString(byte[] digest) {
    return HashingUtils.toHexString(digest);
  }
}
