package dev.razafindratelo.kryptos.hashing;

import static dev.razafindratelo.kryptos.hashing.HashingUtils.BLOCK_SIZE_BYTES;

import java.util.function.Function;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class HMAC implements Function<byte[], byte[]> {

  private static final byte IPAD = 0x36;
  private static final byte OPAD = 0x5C;

  private final Function<byte[], byte[]> hashFunction;
  private final byte[] key;

  public static HMAC of(Function<byte[], byte[]> hashFunction, byte[] key) {
    if (hashFunction == null) throw new IllegalArgumentException("Hash function must not be null");
    if (key == null) throw new IllegalArgumentException("Key must not be null");
    if (key.length == 0) throw new IllegalArgumentException("Key must not be empty");
    return new HMAC(hashFunction, key);
  }

  @Override
  public byte[] apply(byte[] message) {
    if (message == null) throw new IllegalArgumentException("Message must not be null");

    byte[] preparedKey = prepareKey(key);
    byte[] innerKey = xorWithPad(preparedKey, IPAD);
    byte[] outerKey = xorWithPad(preparedKey, OPAD);

    byte[] innerHash = hashFunction.apply(concatenate(innerKey, message));

    return hashFunction.apply(concatenate(outerKey, innerHash));
  }

  public String toHexString(byte[] digest) {
    return HashingUtils.toHexString(digest);
  }

  public byte[] prepareKey(byte[] rawKey) {
    byte[] normalized = rawKey.length > BLOCK_SIZE_BYTES ? hashFunction.apply(rawKey) : rawKey;

    byte[] padded = new byte[BLOCK_SIZE_BYTES];
    System.arraycopy(normalized, 0, padded, 0, normalized.length);

    return padded;
  }

  public byte[] xorWithPad(byte[] key, byte pad) {
    byte[] result = new byte[key.length];
    for (int i = 0; i < key.length; i++) {
      result[i] = (byte) (key[i] ^ pad);
    }
    return result;
  }

  public byte[] concatenate(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length];

    System.arraycopy(a, 0, result, 0, a.length);
    System.arraycopy(b, 0, result, a.length, b.length);

    return result;
  }
}
