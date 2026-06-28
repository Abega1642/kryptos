package dev.razafindratelo.kryptos.hashing;

import static java.lang.String.format;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.Function;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class MD5 implements Function<byte[], byte[]> {

  private static final int INIT_A = 0x67452301;
  private static final int INIT_B = 0xEFCDAB89;
  private static final int INIT_C = 0x98BADCFE;
  private static final int INIT_D = 0x10325476;

  private static final int BLOCK_SIZE_BYTES = 64;
  private static final int MESSAGE_SCHEDULE_SIZE = 16;
  private static final int ROUND_COUNT = 64;
  private static final int LENGTH_FIELD_BYTES = 8;
  private static final int PADDING_THRESHOLD = 56;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;
  private static final int HIGH_BIT = 0x80;

  private static final int[] K = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  };

  private static final int[] SHIFT = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  };

  private static final MD5 INSTANCE = new MD5();

  public static MD5 getInstance() {
    return INSTANCE;
  }

  public byte[] pad(byte[] input) {
    long messageLengthBits = (long) input.length * 8;
    int paddingBytes = PADDING_THRESHOLD - (input.length % BLOCK_SIZE_BYTES);

    if (paddingBytes <= 0) {
      paddingBytes += BLOCK_SIZE_BYTES;
    }

    byte[] padded = new byte[input.length + paddingBytes + LENGTH_FIELD_BYTES];
    System.arraycopy(input, 0, padded, 0, input.length);
    padded[input.length] = (byte) HIGH_BIT;

    ByteBuffer.wrap(padded, padded.length - LENGTH_FIELD_BYTES, LENGTH_FIELD_BYTES)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putLong(messageLengthBits);

    return padded;
  }

  @Override
  public byte[] apply(byte[] input) {
    if (input == null) throw new IllegalArgumentException("Input must not be null");

    byte[] padded = pad(input);
    int[] state = {INIT_A, INIT_B, INIT_C, INIT_D};

    for (int offset = 0; offset < padded.length; offset += BLOCK_SIZE_BYTES) {
      byte[] block = new byte[BLOCK_SIZE_BYTES];
      System.arraycopy(padded, offset, block, 0, BLOCK_SIZE_BYTES);
      int[] messageSchedule = toMessageSchedule(block);
      state = compressBlock(state, messageSchedule);
    }

    return toDigest(state);
  }

  public int[] toMessageSchedule(byte[] block) {
    int[] words = new int[MESSAGE_SCHEDULE_SIZE];
    ByteBuffer buffer = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN);
    for (int i = 0; i < MESSAGE_SCHEDULE_SIZE; i++) {
      words[i] = buffer.getInt();
    }
    return words;
  }

  public int leftRotate(int value, int shift) {
    return (value << shift) | (value >>> (32 - shift));
  }

  public int f(int b, int c, int d) {
    return (b & c) | (~b & d);
  }

  public int g(int b, int c, int d) {
    return (b & d) | (c & ~d);
  }

  public int h(int b, int c, int d) {
    return b ^ c ^ d;
  }

  public int i(int b, int c, int d) {
    return c ^ (b | ~d);
  }

  public int selectMessageWordIndex(int round, int i) {
    return switch (round) {
      case 0 -> i;
      case 1 -> (5 * i + 1) % MESSAGE_SCHEDULE_SIZE;
      case 2 -> (3 * i + 5) % MESSAGE_SCHEDULE_SIZE;
      case 3 -> (7 * i) % MESSAGE_SCHEDULE_SIZE;
      default ->
          throw new IllegalArgumentException(format("Invalid round: %d, must be 0-3", round));
    };
  }

  public int[] compressBlock(int[] state, int[] messageSchedule) {
    int a = state[0];
    int b = state[1];
    int c = state[2];
    int d = state[3];

    for (int i = 0; i < ROUND_COUNT; i++) {
      int round = i / MESSAGE_SCHEDULE_SIZE;
      int auxiliaryResult =
          switch (round) {
            case 0 -> f(b, c, d);
            case 1 -> g(b, c, d);
            case 2 -> h(b, c, d);
            case 3 -> i(b, c, d);
            default -> throw new IllegalStateException(format("Invalid round: %d", round));
          };

      int g = selectMessageWordIndex(round, i % MESSAGE_SCHEDULE_SIZE);
      int temp = d;
      d = c;
      c = b;
      b = b + leftRotate(a + auxiliaryResult + messageSchedule[g] + K[i], SHIFT[i]);
      a = temp;
    }

    return new int[] {state[0] + a, state[1] + b, state[2] + c, state[3] + d};
  }

  public byte[] toDigest(int[] state) {
    ByteBuffer buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    for (int word : state) {
      buffer.putInt(word);
    }
    return buffer.array();
  }

  public String toHexString(byte[] digest) {
    StringBuilder sb = new StringBuilder();
    for (byte b : digest) {
      sb.append(format("%02x", b & UNSIGNED_BYTE_MASK));
    }
    return sb.toString();
  }
}
