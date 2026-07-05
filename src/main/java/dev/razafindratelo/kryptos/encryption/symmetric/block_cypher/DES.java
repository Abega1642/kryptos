package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static java.lang.String.format;

import java.util.function.BiFunction;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DES implements BiFunction<byte[], byte[], byte[]> {

  public static final long KEY_HALF_MASK = 0xFFFFFFFL;
  public static final long WORD_MASK_32 = 0xFFFFFFFFL;
  // FIPS 46-3: Initial Permutation
  private static final int[] IP = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
  };
  // FIPS 46-3: Inverse Initial Permutation
  private static final int[] IP_INVERSE = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
  };
  // FIPS 46-3: Expansion permutation: 32 -> 48 bits
  private static final int[] E = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
  };
  // FIPS 46-3: P permutation: 32 bits
  private static final int[] P = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
  };
  // FIPS 46-3: PC-1: 64 -> 56 bits
  private static final int[] PC1 = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
  };
  // FIPS 46-3: PC-2: 56 -> 48 bits
  private static final int[] PC2 = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
  };
  // FIPS 46-3: left rotation schedule per round
  private static final int[] ROTATION_SCHEDULE = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
  // FIPS 46-3: 8 S-boxes, each maps 6 bits -> 4 bits
  private static final int[][][] S_BOXES = {
    {
      {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
      {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
      {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
      {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
      {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
      {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
      {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
      {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
      {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
      {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
      {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
      {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
      {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
      {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
      {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
      {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
      {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
      {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
      {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
      {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
      {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
      {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
      {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
      {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
      {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
      {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
      {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
      {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
      {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
      {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
      {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
      {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
  };
  private static final int BLOCK_SIZE_BITS = 64;
  private static final int HALF_BLOCK_BITS = 32;
  private static final int KEY_SIZE_BITS = 56;
  private static final int HALF_KEY_BITS = 28;
  private static final int SUBKEY_BITS = 48;
  private static final int ROUNDS = 16;
  private static final int S_BOX_COUNT = 8;
  private static final int S_BOX_INPUT_BITS = 6;
  private static final int S_BOX_OUTPUT_BITS = 4;
  private static final DES INSTANCE = new DES();

  public static DES getInstance() {
    return INSTANCE;
  }

  @Override
  public byte[] apply(byte[] block, byte[] key) {
    if (block == null) throw new IllegalArgumentException("Block must not be null");
    if (key == null) throw new IllegalArgumentException("Key must not be null");
    if (block.length != 8)
      throw new IllegalArgumentException(format("Block must be 8 bytes, got %d", block.length));
    if (key.length != 8)
      throw new IllegalArgumentException(format("Key must be 8 bytes, got %d", key.length));

    return encryptBlock(block, generateSubkeys(key));
  }

  public long permute(long input, int[] table, int inputBits) {
    long output = 0;

    for (int i = 0; i < table.length; i++) {
      int bit = (int) ((input >>> (inputBits - table[i])) & 1L);
      output |= ((long) bit) << (table.length - 1 - i);
    }

    return output;
  }

  public long[] generateSubkeys(byte[] key) {
    long keyBits = bytesToLong(key);
    long permuted = permute(keyBits, PC1, BLOCK_SIZE_BITS);

    long c = (permuted >>> HALF_KEY_BITS) & KEY_HALF_MASK;
    long d = permuted & KEY_HALF_MASK;

    long[] subkeys = new long[ROUNDS];

    for (int i = 0; i < ROUNDS; i++) {
      c = rotateLeft28(c, ROTATION_SCHEDULE[i]);
      d = rotateLeft28(d, ROTATION_SCHEDULE[i]);
      long cd = (c << HALF_KEY_BITS) | d;
      subkeys[i] = permute(cd, PC2, KEY_SIZE_BITS);
    }

    return subkeys;
  }

  public long expand(long halfBlock) {
    return permute(halfBlock, E, HALF_BLOCK_BITS);
  }

  public long applySBoxes(long input) {
    long output = 0;

    for (int i = 0; i < S_BOX_COUNT; i++) {
      int sixBits = (int) ((input >>> (SUBKEY_BITS - S_BOX_INPUT_BITS * (i + 1))) & 0x3FL);
      int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
      int col = (sixBits >> 1) & 0x0F;
      int sVal = S_BOXES[i][row][col];
      output |= ((long) sVal) << (HALF_BLOCK_BITS - S_BOX_OUTPUT_BITS * (i + 1));
    }

    return output;
  }

  public long feistelF(long halfBlock, long subkey) {
    long expanded = expand(halfBlock);
    long xored = expanded ^ subkey;
    long sBoxed = applySBoxes(xored);

    return permute(sBoxed, P, HALF_BLOCK_BITS);
  }

  public long[] feistelRound(long left, long right, long subkey) {
    return new long[] {right, left ^ feistelF(right, subkey)};
  }

  public byte[] encryptBlock(byte[] block, long[] subkeys) {
    long input = bytesToLong(block);
    long permuted = permute(input, IP, BLOCK_SIZE_BITS);

    long left = (permuted >>> HALF_BLOCK_BITS) & WORD_MASK_32;
    long right = permuted & WORD_MASK_32;

    for (int i = 0; i < ROUNDS; i++) {
      long[] result = feistelRound(left, right, subkeys[i]);
      left = result[0];
      right = result[1];
    }

    long combined = (right << HALF_BLOCK_BITS) | left;
    long cipher = permute(combined, IP_INVERSE, BLOCK_SIZE_BITS);

    return longToBytes(cipher);
  }

  public byte[] decryptBlock(byte[] block, long[] subkeys) {
    long[] reversed = new long[ROUNDS];

    for (int i = 0; i < ROUNDS; i++) {
      reversed[i] = subkeys[ROUNDS - 1 - i];
    }

    return encryptBlock(block, reversed);
  }

  private long rotateLeft28(long value, int shift) {
    return ((value << shift) | (value >>> (HALF_KEY_BITS - shift))) & KEY_HALF_MASK;
  }

  private long bytesToLong(byte[] bytes) {
    long result = 0;

    for (int i = 0; i < 8; i++) {
      result = (result << 8) | (bytes[i] & 0xFFL);
    }

    return result;
  }

  private byte[] longToBytes(long value) {
    byte[] bytes = new byte[8];

    for (int i = 7; i >= 0; i--) {
      bytes[i] = (byte) (value & 0xFFL);
      value >>>= 8;
    }

    return bytes;
  }
}
