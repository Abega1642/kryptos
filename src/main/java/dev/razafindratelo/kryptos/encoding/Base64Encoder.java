package dev.razafindratelo.kryptos.encoding;

import java.util.function.Function;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public final class Base64Encoder implements Function<byte[], String> {

  public static final byte[] STANDARD_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes();

  public static final byte[] URL_SAFE_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".getBytes();

  public static final byte PADDING = '=';

  public static final int UNSIGNED_BYTE_MASK = 0xFF;
  public static final int SIX_BIT_MASK = 0x3F;
  public static final int FOUR_BIT_MASK = 0x0F;
  public static final int TWO_BIT_MASK = 0x03;

  private final byte[] alphabet;

  public static Base64Encoder standard() {
    return new Base64Encoder(STANDARD_ALPHABET);
  }

  public static Base64Encoder urlSafe() {
    return new Base64Encoder(URL_SAFE_ALPHABET);
  }

  @Override
  public String apply(byte[] input) {
    if (input == null) throw new IllegalArgumentException("Input must not be null");
    if (input.length == 0) return "";

    int remainder = input.length % 3;
    int completeGroupLength = input.length / 3;

    byte[] encodedCompleteGroup = encodeFullGroups(input, completeGroupLength);
    byte[] encodedRemainder = encodeRemainder(input, completeGroupLength, remainder);

    byte[] output = new byte[encodedCompleteGroup.length + encodedRemainder.length];

    System.arraycopy(encodedCompleteGroup, 0, output, 0, encodedCompleteGroup.length);
    System.arraycopy(
        encodedRemainder, 0, output, encodedCompleteGroup.length, encodedRemainder.length);

    return new String(output);
  }

  public byte[] encodeFullGroups(byte[] input, int fullGroups) {
    byte[] output = new byte[fullGroups * 4];
    int outputIndex = 0;

    for (int i = 0; i < fullGroups * 3; i += 3) {
      int b0 = input[i] & UNSIGNED_BYTE_MASK;
      int b1 = input[i + 1] & UNSIGNED_BYTE_MASK;
      int b2 = input[i + 2] & UNSIGNED_BYTE_MASK;

      byte[] encoded = encodeFullGroup(b0, b1, b2);
      output[outputIndex++] = encoded[0];
      output[outputIndex++] = encoded[1];
      output[outputIndex++] = encoded[2];
      output[outputIndex++] = encoded[3];
    }

    return output;
  }

  public byte[] encodeFullGroup(int b0, int b1, int b2) {
    return new byte[] {
      alphabet[(b0 >> 2) & SIX_BIT_MASK],
      alphabet[((b0 & TWO_BIT_MASK) << 4) | ((b1 >> 4) & FOUR_BIT_MASK)],
      alphabet[((b1 & FOUR_BIT_MASK) << 2) | ((b2 >> 6) & TWO_BIT_MASK)],
      alphabet[b2 & SIX_BIT_MASK]
    };
  }

  public byte[] encodeRemainder(byte[] input, int fullGroups, int remainder) {
    int start = fullGroups * 3;

    return switch (remainder) {
      case 1 -> encodeOneByteRemainder(input[start] & UNSIGNED_BYTE_MASK);
      case 2 ->
          encodeTwoByteRemainder(
              input[start] & UNSIGNED_BYTE_MASK, input[start + 1] & UNSIGNED_BYTE_MASK);
      default -> new byte[0];
    };
  }

  public byte[] encodeOneByteRemainder(int b0) {
    return new byte[] {
      alphabet[(b0 >> 2) & SIX_BIT_MASK], alphabet[(b0 & TWO_BIT_MASK) << 4], PADDING, PADDING
    };
  }

  public byte[] encodeTwoByteRemainder(int b0, int b1) {
    return new byte[] {
      alphabet[(b0 >> 2) & SIX_BIT_MASK],
      alphabet[((b0 & TWO_BIT_MASK) << 4) | ((b1 >> 4) & FOUR_BIT_MASK)],
      alphabet[(b1 & FOUR_BIT_MASK) << 2],
      PADDING
    };
  }
}
