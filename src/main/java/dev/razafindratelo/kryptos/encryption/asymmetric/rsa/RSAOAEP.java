package dev.razafindratelo.kryptos.encryption.asymmetric.rsa;

import static java.lang.String.format;

import dev.razafindratelo.kryptos.hashing.SHA256;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class RSAOAEP {

  private static final SHA256 SHA_256 = SHA256.getInstance();
  private static final int H_LEN = 32;
  private static final byte ZERO_BYTE = 0x00;
  private static final byte ONE_BYTE = 0x01;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;

  private final TextbookRSA textbookRSA;
  private final SecureRandom secureRandom;

  public static RSAOAEP getInstance() {
    return new RSAOAEP(TextbookRSA.getInstance(), new SecureRandom());
  }

  public byte[] mgf1(byte[] seed, int length) {
    if (seed == null) throw new IllegalArgumentException("Seed must not be null");
    if (length <= 0)
      throw new IllegalArgumentException(format("Length must be positive, got %d", length));

    byte[] output = new byte[length];
    int offset = 0;
    int counter = 0;

    while (offset < length) {
      byte[] counterBytes = intToBytes(counter);
      byte[] input = concatenate(seed, counterBytes);
      byte[] hash = SHA_256.apply(input);
      int toCopy = Math.min(H_LEN, length - offset);
      System.arraycopy(hash, 0, output, offset, toCopy);
      offset += toCopy;
      counter++;
    }

    return output;
  }

  public byte[] pad(byte[] message, int modulusBytes) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");

    int maxMessageLength = modulusBytes - 2 * H_LEN - 2;
    if (message.length > maxMessageLength)
      throw new IllegalArgumentException(
          format("Message too long: max %d bytes, got %d", maxMessageLength, message.length));

    byte[] lHash = SHA_256.apply(new byte[0]);
    int dbLen = modulusBytes - H_LEN - 1;
    byte[] db = new byte[dbLen];

    System.arraycopy(lHash, 0, db, 0, H_LEN);
    db[dbLen - message.length - 1] = ONE_BYTE;
    System.arraycopy(message, 0, db, dbLen - message.length, message.length);

    byte[] seed = new byte[H_LEN];
    secureRandom.nextBytes(seed);

    byte[] dbMask = mgf1(seed, dbLen);
    byte[] maskedDB = xor(db, dbMask);
    byte[] seedMask = mgf1(maskedDB, H_LEN);
    byte[] maskedSeed = xor(seed, seedMask);

    byte[] em = new byte[modulusBytes];
    em[0] = ZERO_BYTE;
    System.arraycopy(maskedSeed, 0, em, 1, H_LEN);
    System.arraycopy(maskedDB, 0, em, 1 + H_LEN, dbLen);

    return em;
  }

  public byte[] unpad(byte[] em, int modulusBytes) {
    if (em == null) throw new IllegalArgumentException("Encoded message must not be null");

    if (em[0] != ZERO_BYTE)
      throw new IllegalArgumentException("Invalid OAEP encoding: first byte must be 0x00");

    int dbLen = modulusBytes - H_LEN - 1;
    byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + H_LEN);
    byte[] maskedDB = Arrays.copyOfRange(em, 1 + H_LEN, modulusBytes);

    byte[] seedMask = mgf1(maskedDB, H_LEN);
    byte[] seed = xor(maskedSeed, seedMask);
    byte[] dbMask = mgf1(seed, dbLen);
    byte[] db = xor(maskedDB, dbMask);

    byte[] lHash = SHA_256.apply(new byte[0]);
    byte[] lHashPrime = Arrays.copyOfRange(db, 0, H_LEN);

    if (!Arrays.equals(lHash, lHashPrime))
      throw new IllegalArgumentException("Invalid OAEP encoding: label hash mismatch");

    int i = H_LEN;
    while (i < db.length && db[i] == ZERO_BYTE) i++;

    if (i >= db.length || db[i] != ONE_BYTE)
      throw new IllegalArgumentException("Invalid OAEP encoding: missing 0x01 separator");

    return Arrays.copyOfRange(db, i + 1, db.length);
  }

  public byte[] encrypt(byte[] message, RSAPublicKey publicKey) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");
    if (publicKey == null) throw new IllegalArgumentException("Public key must not be null");

    int modulusBytes = (publicKey.n().bitLength() + 7) / 8;
    byte[] em = pad(message, modulusBytes);
    BigInteger m = new BigInteger(1, em);
    BigInteger c = textbookRSA.encrypt(m, publicKey);
    return toFixedLengthBytes(c, modulusBytes);
  }

  public byte[] decrypt(byte[] ciphertext, RSAPrivateKey privateKey) {
    if (ciphertext == null) throw new IllegalArgumentException("Ciphertext must not be null");
    if (privateKey == null) throw new IllegalArgumentException("Private key must not be null");

    int modulusBytes = (privateKey.n().bitLength() + 7) / 8;
    BigInteger c = new BigInteger(1, ciphertext);
    BigInteger m = textbookRSA.decrypt(c, privateKey);
    byte[] em = toFixedLengthBytes(m, modulusBytes);
    return unpad(em, modulusBytes);
  }

  public byte[] xor(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }

  private byte[] concatenate(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length];
    System.arraycopy(a, 0, result, 0, a.length);
    System.arraycopy(b, 0, result, a.length, b.length);
    return result;
  }

  private byte[] intToBytes(int value) {
    return new byte[] {
      (byte) ((value >>> 24) & UNSIGNED_BYTE_MASK),
      (byte) ((value >>> 16) & UNSIGNED_BYTE_MASK),
      (byte) ((value >>> 8) & UNSIGNED_BYTE_MASK),
      (byte) (value & UNSIGNED_BYTE_MASK)
    };
  }

  private byte[] toFixedLengthBytes(BigInteger value, int length) {
    byte[] bytes = value.toByteArray();
    byte[] result = new byte[length];

    if (bytes.length > length) {
      System.arraycopy(bytes, bytes.length - length, result, 0, length);
    } else {
      System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
    }

    return result;
  }
}
