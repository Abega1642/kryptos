package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import static java.lang.String.format;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class AESCBC {

  private static final int BLOCK_SIZE = 16;
  private static final int IV_SIZE = 16;

  private final AESVariant variant;

  public static AESCBC of(AESVariant variant) {
    if (variant == null) throw new IllegalArgumentException("Variant must not be null");

    return new AESCBC(variant);
  }

  public byte[] encrypt(byte[] block, byte[] key, byte[] iv) {
    validate(block, key, iv);

    AES aes = AES.of(variant);
    byte[] xored = xor(block, iv);

    return aes.encrypt(xored, key);
  }

  public byte[] decrypt(byte[] block, byte[] key, byte[] iv) {
    validate(block, key, iv);
    AES aes = AES.of(variant);
    byte[] decrypted = aes.decrypt(block, key);

    return xor(decrypted, iv);
  }

  public byte[] xor(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];

    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }

    return result;
  }

  private void validate(byte[] block, byte[] key, byte[] iv) {
    if (block == null) throw new IllegalArgumentException("Block must not be null");

    if (key == null) throw new IllegalArgumentException("Key must not be null");

    if (iv == null) throw new IllegalArgumentException("IV must not be null");

    if (block.length != BLOCK_SIZE)
      throw new IllegalArgumentException(
          format("Block must be %d bytes, got %d", BLOCK_SIZE, block.length));

    if (iv.length != IV_SIZE)
      throw new IllegalArgumentException(format("IV must be %d bytes, got %d", IV_SIZE, iv.length));

    if (key.length != variant.getKeyBytes())
      throw new IllegalArgumentException(
          format(
              "Key must be %d bytes for %s, got %d", variant.getKeyBytes(), variant, key.length));
  }
}
