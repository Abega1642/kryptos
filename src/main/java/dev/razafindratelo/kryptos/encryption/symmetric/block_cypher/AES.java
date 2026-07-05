package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static dev.razafindratelo.kryptos.encoding.Base64Encoder.UNSIGNED_BYTE_MASK;
import static dev.razafindratelo.kryptos.hashing.HashingUtils.HIGH_BIT;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class AES {

  private static final int BLOCK_SIZE = 16;
  private static final int WORD_SIZE = 4;
  private static final int STATE_ROWS = 4;
  private static final int STATE_COLS = 4;

  private static final int[] S_BOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };

  private static final int[] INV_S_BOX = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  };

  private static final int[] RCON = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
  };

  private final AESVariant variant;

  public static AES of(AESVariant variant) {
    if (variant == null) throw new IllegalArgumentException("Variant must not be null");
    return new AES(variant);
  }

  public byte[][] toState(byte[] block) {
    byte[][] state = new byte[STATE_ROWS][STATE_COLS];
    for (int col = 0; col < STATE_COLS; col++) {
      for (int row = 0; row < STATE_ROWS; row++) {
        state[row][col] = block[col * STATE_ROWS + row];
      }
    }
    return state;
  }

  public byte[] fromState(byte[][] state) {
    byte[] block = new byte[BLOCK_SIZE];
    for (int col = 0; col < STATE_COLS; col++) {
      for (int row = 0; row < STATE_ROWS; row++) {
        block[col * STATE_ROWS + row] = state[row][col];
      }
    }
    return block;
  }

  public int xtime(int b) {
    return ((b << 1) ^ (((b & HIGH_BIT) != 0) ? 0x1b : 0x00)) & UNSIGNED_BYTE_MASK;
  }

  public int gfMultiply(int a, int b) {
    int result = 0;
    int temp = a & UNSIGNED_BYTE_MASK;
    while (b > 0) {
      if ((b & 1) != 0) result ^= temp;
      temp = xtime(temp);
      b >>= 1;
    }
    return result & UNSIGNED_BYTE_MASK;
  }

  public byte[][] subBytes(byte[][] state) {
    return applySubstitution(state, S_BOX);
  }

  public byte[][] invSubBytes(byte[][] state) {
    return applySubstitution(state, INV_S_BOX);
  }

  private byte[][] applySubstitution(byte[][] state, int[] box) {
    byte[][] result = new byte[STATE_ROWS][STATE_COLS];
    for (int row = 0; row < STATE_ROWS; row++) {
      for (int col = 0; col < STATE_COLS; col++) {
        result[row][col] = (byte) box[state[row][col] & UNSIGNED_BYTE_MASK];
      }
    }
    return result;
  }

  public byte[][] shiftRows(byte[][] state) {
    return applyShift(state, 1);
  }

  public byte[][] invShiftRows(byte[][] state) {
    return applyShift(state, -1);
  }

  private byte[][] applyShift(byte[][] state, int direction) {
    byte[][] result = new byte[STATE_ROWS][STATE_COLS];
    for (int row = 0; row < STATE_ROWS; row++) {
      for (int col = 0; col < STATE_COLS; col++) {
        result[row][col] =
            state[row][(col + direction * row + STATE_COLS * STATE_ROWS) % STATE_COLS];
      }
    }
    return result;
  }

  public byte[][] mixColumns(byte[][] state) {
    byte[][] result = new byte[STATE_ROWS][STATE_COLS];
    for (int col = 0; col < STATE_COLS; col++) {
      int s0 = state[0][col] & UNSIGNED_BYTE_MASK;
      int s1 = state[1][col] & UNSIGNED_BYTE_MASK;
      int s2 = state[2][col] & UNSIGNED_BYTE_MASK;
      int s3 = state[3][col] & UNSIGNED_BYTE_MASK;

      result[0][col] = (byte) (gfMultiply(0x02, s0) ^ gfMultiply(0x03, s1) ^ s2 ^ s3);
      result[1][col] = (byte) (s0 ^ gfMultiply(0x02, s1) ^ gfMultiply(0x03, s2) ^ s3);
      result[2][col] = (byte) (s0 ^ s1 ^ gfMultiply(0x02, s2) ^ gfMultiply(0x03, s3));
      result[3][col] = (byte) (gfMultiply(0x03, s0) ^ s1 ^ s2 ^ gfMultiply(0x02, s3));
    }
    return result;
  }

  public byte[][] invMixColumns(byte[][] state) {
    byte[][] result = new byte[STATE_ROWS][STATE_COLS];
    for (int col = 0; col < STATE_COLS; col++) {
      int s0 = state[0][col] & UNSIGNED_BYTE_MASK;
      int s1 = state[1][col] & UNSIGNED_BYTE_MASK;
      int s2 = state[2][col] & UNSIGNED_BYTE_MASK;
      int s3 = state[3][col] & UNSIGNED_BYTE_MASK;

      result[0][col] =
          (byte)
              (gfMultiply(0x0e, s0)
                  ^ gfMultiply(0x0b, s1)
                  ^ gfMultiply(0x0d, s2)
                  ^ gfMultiply(0x09, s3));
      result[1][col] =
          (byte)
              (gfMultiply(0x09, s0)
                  ^ gfMultiply(0x0e, s1)
                  ^ gfMultiply(0x0b, s2)
                  ^ gfMultiply(0x0d, s3));
      result[2][col] =
          (byte)
              (gfMultiply(0x0d, s0)
                  ^ gfMultiply(0x09, s1)
                  ^ gfMultiply(0x0e, s2)
                  ^ gfMultiply(0x0b, s3));
      result[3][col] =
          (byte)
              (gfMultiply(0x0b, s0)
                  ^ gfMultiply(0x0d, s1)
                  ^ gfMultiply(0x09, s2)
                  ^ gfMultiply(0x0e, s3));
    }
    return result;
  }

  public byte[][] addRoundKey(byte[][] state, int[][] roundKey) {
    byte[][] result = new byte[STATE_ROWS][STATE_COLS];
    for (int row = 0; row < STATE_ROWS; row++) {
      for (int col = 0; col < STATE_COLS; col++) {
        result[row][col] = (byte) ((state[row][col] & UNSIGNED_BYTE_MASK) ^ roundKey[row][col]);
      }
    }
    return result;
  }

  public int[] subWord(int[] word) {
    int[] result = new int[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; i++) {
      result[i] = S_BOX[word[i] & UNSIGNED_BYTE_MASK];
    }
    return result;
  }

  public int[] rotWord(int[] word) {
    return new int[] {word[1], word[2], word[3], word[0]};
  }

  public int[][][] keyExpansion(byte[] key) {
    int nk = variant.getKeyBytes() / WORD_SIZE;
    int rounds = variant.getRounds();
    int totalWords = (rounds + 1) * STATE_COLS;

    int[][] w = new int[totalWords][WORD_SIZE];

    for (int i = 0; i < nk; i++) {
      w[i] =
          new int[] {
            key[i * WORD_SIZE] & UNSIGNED_BYTE_MASK,
            key[i * WORD_SIZE + 1] & UNSIGNED_BYTE_MASK,
            key[i * WORD_SIZE + 2] & UNSIGNED_BYTE_MASK,
            key[i * WORD_SIZE + 3] & UNSIGNED_BYTE_MASK
          };
    }

    for (int i = nk; i < totalWords; i++) {
      int[] temp = w[i - 1].clone();
      if (i % nk == 0) {
        temp = subWord(rotWord(temp));
        temp[0] ^= RCON[i / nk];
      } else if (nk > 6 && i % nk == 4) {
        temp = subWord(temp);
      }
      for (int j = 0; j < WORD_SIZE; j++) {
        w[i][j] = w[i - nk][j] ^ temp[j];
      }
    }

    int[][][] roundKeys = new int[rounds + 1][STATE_ROWS][STATE_COLS];
    for (int round = 0; round <= rounds; round++) {
      for (int col = 0; col < STATE_COLS; col++) {
        for (int row = 0; row < STATE_ROWS; row++) {
          roundKeys[round][row][col] = w[round * STATE_COLS + col][row];
        }
      }
    }

    return roundKeys;
  }

  public byte[] encrypt(byte[] block, byte[] key) {
    validateInput(block, key);

    int[][][] roundKeys = keyExpansion(key);
    byte[][] state = toState(block);
    int rounds = variant.getRounds();

    state = addRoundKey(state, roundKeys[0]);

    for (int round = 1; round < rounds; round++) {
      state = subBytes(state);
      state = shiftRows(state);
      state = mixColumns(state);
      state = addRoundKey(state, roundKeys[round]);
    }

    state = subBytes(state);
    state = shiftRows(state);
    state = addRoundKey(state, roundKeys[rounds]);

    return fromState(state);
  }

  public byte[] decrypt(byte[] block, byte[] key) {
    validateInput(block, key);

    int[][][] roundKeys = keyExpansion(key);
    byte[][] state = toState(block);
    int rounds = variant.getRounds();

    state = addRoundKey(state, roundKeys[rounds]);

    for (int round = rounds - 1; round >= 1; round--) {
      state = invShiftRows(state);
      state = invSubBytes(state);
      state = addRoundKey(state, roundKeys[round]);
      state = invMixColumns(state);
    }

    state = invShiftRows(state);
    state = invSubBytes(state);
    state = addRoundKey(state, roundKeys[0]);

    return fromState(state);
  }

  private void validateInput(byte[] block, byte[] key) {
    if (block == null) throw new IllegalArgumentException("Block must not be null");
    if (key == null) throw new IllegalArgumentException("Key must not be null");
    if (block.length != BLOCK_SIZE)
      throw new IllegalArgumentException(
          String.format("Block must be %d bytes, got %d", BLOCK_SIZE, block.length));
    if (key.length != variant.getKeyBytes())
      throw new IllegalArgumentException(
          String.format(
              "Key must be %d bytes for %s, got %d", variant.getKeyBytes(), variant, key.length));
  }
}
