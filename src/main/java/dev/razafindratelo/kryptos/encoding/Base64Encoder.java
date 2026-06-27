package dev.razafindratelo.kryptos.encoding;

import java.util.function.Function;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public final class Base64Encoder implements Function<byte[], String> {

  private static final byte[] STANDARD_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes();

  private static final byte[] URL_SAFE_ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".getBytes();

  private static final byte PADDING = '=';

  private final byte[] alphabet;

  public static Base64Encoder standard() {
    return new Base64Encoder(STANDARD_ALPHABET);
  }

  public static Base64Encoder urlSafe() {
    return new Base64Encoder(URL_SAFE_ALPHABET);
  }

  public byte[] encodeFullGroups(byte[] input, int fullGroups) {
    byte[] output = new byte[fullGroups * 4];
    int outputIndex = 0;

    for (int i = 0; i < fullGroups * 3; i += 3) {
      int b0 = input[i] & 0xFF;
      int b1 = input[i + 1] & 0xFF;
      int b2 = input[i + 2] & 0xFF;

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
      alphabet[(b0 >> 2) & 0x3F],
      alphabet[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)],
      alphabet[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)],
      alphabet[b2 & 0x3F]
    };
  }

  public byte[] encodeRemainder(byte[] input, int fullGroups, int remainder) {
    int start = fullGroups * 3;

    return switch (remainder) {
      case 1 -> encodeOneByteRemainder(input[start] & 0xFF);
      case 2 -> encodeTwoByteRemainder(input[start] & 0xFF, input[start + 1] & 0xFF);
      default -> new byte[0];
    };
  }

  public byte[] encodeOneByteRemainder(int b0) {
    return new byte[] {alphabet[(b0 >> 2) & 0x3F], alphabet[(b0 & 0x03) << 4], PADDING, PADDING};
  }

  public byte[] encodeTwoByteRemainder(int b0, int b1) {
    return new byte[] {
      alphabet[(b0 >> 2) & 0x3F],
      alphabet[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)],
      alphabet[(b1 & 0x0F) << 2],
      PADDING
    };
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
}
