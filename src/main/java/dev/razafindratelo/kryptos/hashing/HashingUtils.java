package dev.razafindratelo.kryptos.hashing;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class HashingUtils {

  public static final int BLOCK_SIZE_BYTES = 64;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;
  private static final int HIGH_BIT = 0x80;
  private static final int LENGTH_FIELD_BYTES = 8;
  private static final int PADDING_THRESHOLD = 56;

  public static byte[] pad(byte[] input, ByteOrder byteOrder) {
    long messageLengthBits = (long) input.length * 8;
    int paddingBytes = PADDING_THRESHOLD - (input.length % BLOCK_SIZE_BYTES);

    if (paddingBytes <= 0) {
      paddingBytes += BLOCK_SIZE_BYTES;
    }

    byte[] padded = new byte[input.length + paddingBytes + LENGTH_FIELD_BYTES];
    System.arraycopy(input, 0, padded, 0, input.length);
    padded[input.length] = (byte) HIGH_BIT;

    ByteBuffer.wrap(padded, padded.length - LENGTH_FIELD_BYTES, LENGTH_FIELD_BYTES)
        .order(byteOrder)
        .putLong(messageLengthBits);

    return padded;
  }

  public static byte[][] splitIntoBlocks(byte[] padded, int blockSize) {
    int blockCount = padded.length / blockSize;
    byte[][] blocks = new byte[blockCount][blockSize];

    for (int i = 0; i < blockCount; i++) {
      System.arraycopy(padded, i * blockSize, blocks[i], 0, blockSize);
    }

    return blocks;
  }

  public static String toHexString(byte[] digest) {
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
      sb.append(String.format("%02x", b & UNSIGNED_BYTE_MASK));
    }
    return sb.toString();
  }

  public static byte[] toDigest(int[] state, ByteOrder byteOrder) {
    ByteBuffer buffer = ByteBuffer.allocate(state.length * 4).order(byteOrder);
    for (int word : state) {
      buffer.putInt(word);
    }
    return buffer.array();
  }
}
