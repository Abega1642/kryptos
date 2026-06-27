package dev.razafindratelo.kryptos.encoding;

import static dev.razafindratelo.kryptos.encoding.Base64Encoder.STANDARD_ALPHABET;
import static dev.razafindratelo.kryptos.encoding.Base64Encoder.URL_SAFE_ALPHABET;
import static java.lang.String.format;

import java.util.Arrays;
import java.util.function.Function;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public final class Base64Decoder implements Function<String, byte[]> {

  private static final byte INVALID = -1;
  private final byte[] reverseAlphabet;

  public static Base64Decoder standard() {
    return new Base64Decoder(buildReverseAlphabet(STANDARD_ALPHABET));
  }

  public static Base64Decoder urlSafe() {
    return new Base64Decoder(buildReverseAlphabet(URL_SAFE_ALPHABET));
  }

  private static byte[] buildReverseAlphabet(byte[] alphabet) {
    byte[] reverse = new byte[256];
    Arrays.fill(reverse, INVALID);
    for (int i = 0; i < alphabet.length; i++) {
      reverse[alphabet[i]] = (byte) i;
    }
    return reverse;
  }

  private int lookupCharacter(byte character) {
    int value = reverseAlphabet[character & 0xFF];
    if (value == INVALID) {
      throw new IllegalArgumentException(
          String.format(
              "Invalid Base64 character: '%c' (ASCII %d)", (char) character, character & 0xFF));
    }
    return value;
  }

  public int countPadding(String input) {
    int count = 0;
    if (input.charAt(input.length() - 1) == '=') count++;
    if (input.charAt(input.length() - 2) == '=') count++;

    return count;
  }

  public byte[] decodeFullGroup(int c0, int c1, int c2, int c3) {
    return new byte[] {
      (byte) ((c0 << 2) | (c1 >> 4)),
      (byte) (((c1 & 0x0F) << 4) | (c2 >> 2)),
      (byte) (((c2 & 0x03) << 6) | c3)
    };
  }

  public byte[] decodeFullGroups(byte[] input, int fullGroups) {
    byte[] output = new byte[fullGroups * 3];
    int outputIndex = 0;

    for (int i = 0; i < fullGroups * 4; i += 4) {
      int c0 = lookupCharacter(input[i]);
      int c1 = lookupCharacter(input[i + 1]);
      int c2 = lookupCharacter(input[i + 2]);
      int c3 = lookupCharacter(input[i + 3]);

      byte[] decoded = decodeFullGroup(c0, c1, c2, c3);
      output[outputIndex++] = decoded[0];
      output[outputIndex++] = decoded[1];
      output[outputIndex++] = decoded[2];
    }

    return output;
  }

  public byte[] decodeRemainder(byte[] input, int fullGroups, int paddingCount) {
    int start = fullGroups * 4;

    int c0 = lookupCharacter(input[start]);
    int c1 = lookupCharacter(input[start + 1]);

    if (paddingCount == 2) {
      return decodeOneByteRemainder(c0, c1);
    }

    int c2 = lookupCharacter(input[start + 2]);
    return decodeTwoByteRemainder(c0, c1, c2);
  }

  public byte[] decodeOneByteRemainder(int c0, int c1) {
    return new byte[] {(byte) ((c0 << 2) | (c1 >> 4))};
  }

  public byte[] decodeTwoByteRemainder(int c0, int c1, int c2) {
    return new byte[] {(byte) ((c0 << 2) | (c1 >> 4)), (byte) (((c1 & 0x0F) << 4) | (c2 >> 2))};
  }

  @Override
  public byte[] apply(String input) {
    if (input == null) throw new IllegalArgumentException("Input must not be null");
    if (input.isEmpty()) return new byte[0];
    if (input.length() % 4 != 0)
      throw new IllegalArgumentException(
          format("Invalid Base64 input length: %d, must be a multiple of 4", input.length()));

    byte[] inputBytes = input.getBytes();
    int paddingCount = countPadding(input);
    int fullGroups = (inputBytes.length / 4) - (paddingCount > 0 ? 1 : 0);

    byte[] decodedFullGroups = decodeFullGroups(inputBytes, fullGroups);
    byte[] decodedRemainder =
        paddingCount > 0 ? decodeRemainder(inputBytes, fullGroups, paddingCount) : new byte[0];

    byte[] output = new byte[decodedFullGroups.length + decodedRemainder.length];
    System.arraycopy(decodedFullGroups, 0, output, 0, decodedFullGroups.length);
    System.arraycopy(
        decodedRemainder, 0, output, decodedFullGroups.length, decodedRemainder.length);

    return output;
  }
}
