package dev.razafindratelo.kryptos.hashing.bcrypt;

import dev.razafindratelo.kryptos.encryption.symmetric.block_cypher.Blowfish;
import java.security.SecureRandom;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Bcrypt {

  private static final String VERSION = "2b";
  private static final int DEFAULT_COST = 12;
  private static final int SALT_BYTES = 16;
  private static final int HASH_BYTES = 23;
  private static final int ENCRYPT_ROUNDS = 64;
  private static final int UNSIGNED_BYTE_MASK = 0xFF;

  // bcrypt custom Base64 alphabet -- different from standard Base64
  private static final String ALPHABET =
      "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  // "OrpheanBeholderScryDoubt" as three 64-bit blocks
  private static final long[] MAGIC = {
    0x4f727068L << 32 | 0x65616e42L,
    0x65686f6cL << 32 | 0x64657253L,
    0x63727944L << 32 | 0x6f756274L
  };

  private static final Bcrypt INSTANCE = new Bcrypt();

  public static Bcrypt getInstance() {
    return INSTANCE;
  }

  public String hash(String password) {
    return hash(password, DEFAULT_COST);
  }

  public String hash(String password, int cost) {
    if (password == null || password.isEmpty())
      throw new IllegalArgumentException("Password must not be null or empty");
    if (cost < 4 || cost > 31)
      throw new IllegalArgumentException(
          String.format("Cost must be between 4 and 31, got %d", cost));

    byte[] salt = generateSalt();
    return hash(password, cost, salt);
  }

  public String hash(String password, int cost, byte[] salt) {
    if (password == null || password.isEmpty())
      throw new IllegalArgumentException("Password must not be null or empty");
    if (salt == null || salt.length != SALT_BYTES)
      throw new IllegalArgumentException("Salt must be exactly 16 bytes");

    byte[] passwordBytes = toNullTerminated(password.getBytes());
    int[] state = BcryptKeySchedule.getInstance().eksBlowfishSetup(cost, salt, passwordBytes);

    byte[] rawHash = encryptMagic(state);
    return formatHash(VERSION, cost, salt, rawHash);
  }

  public boolean verify(String password, String hashed) {
    if (password == null || password.isEmpty())
      throw new IllegalArgumentException("Password must not be null or empty");
    if (hashed == null || hashed.isEmpty())
      throw new IllegalArgumentException("Hash must not be null or empty");

    ParsedHash parsed = parseHash(hashed);
    byte[] passwordBytes = toNullTerminated(password.getBytes());
    int[] state =
        BcryptKeySchedule.getInstance()
            .eksBlowfishSetup(parsed.cost(), parsed.salt(), passwordBytes);
    byte[] rawHash = encryptMagic(state);
    String recomputed = formatHash(parsed.version(), parsed.cost(), parsed.salt(), rawHash);
    return constantTimeEquals(hashed, recomputed);
  }

  public byte[] generateSalt() {
    byte[] salt = new byte[SALT_BYTES];
    new SecureRandom().nextBytes(salt);
    return salt;
  }

  public byte[] encryptMagic(int[] state) {
    Blowfish blowfish = Blowfish.getInstance();
    int[] p = extractP(state);
    int[][] s = extractS(state);

    long[] ciphertext = MAGIC.clone();

    for (int i = 0; i < ENCRYPT_ROUNDS; i++) {
      for (int j = 0; j < ciphertext.length; j++) {
        long[] result =
            blowfish.encryptBlock(ciphertext[j] >>> 32, ciphertext[j] & 0xFFFFFFFFL, p, s);
        ciphertext[j] = (result[0] << 32) | result[1];
      }
    }

    byte[] output = new byte[HASH_BYTES];
    int offset = 0;
    for (long word : ciphertext) {
      for (int i = 7; i >= 0 && offset < HASH_BYTES; i--) {
        output[offset++] = (byte) ((word >>> (i * 8)) & UNSIGNED_BYTE_MASK);
      }
    }
    return output;
  }

  public String bcryptBase64Encode(byte[] data, int inputLength) {
    StringBuilder sb = new StringBuilder();
    int i = 0;
    int c1, c2;

    while (i < inputLength) {
      c1 = data[i++] & UNSIGNED_BYTE_MASK;
      sb.append(ALPHABET.charAt(c1 >> 2));
      c1 = (c1 & 0x03) << 4;
      if (i >= inputLength) {
        sb.append(ALPHABET.charAt(c1));
        break;
      }

      c2 = data[i++] & UNSIGNED_BYTE_MASK;
      c1 |= (c2 >> 4) & 0x0F;
      sb.append(ALPHABET.charAt(c1));
      c1 = (c2 & 0x0F) << 2;
      if (i >= inputLength) {
        sb.append(ALPHABET.charAt(c1));
        break;
      }

      c2 = data[i++] & UNSIGNED_BYTE_MASK;
      c1 |= (c2 >> 6) & 0x03;
      sb.append(ALPHABET.charAt(c1));
      sb.append(ALPHABET.charAt(c2 & 0x3F));
    }

    return sb.toString();
  }

  public byte[] decodeBase64(String encoded, int outputLength) {
    byte[] output = new byte[outputLength];
    int outIndex = 0;
    int i = 0;
    int len = encoded.length();
    int c1, c2;

    while (outIndex < outputLength && i < len) {
      c1 = ALPHABET.indexOf(encoded.charAt(i++));
      if (i >= len) break;
      c2 = ALPHABET.indexOf(encoded.charAt(i++));
      output[outIndex++] = (byte) ((c1 << 2) | ((c2 & 0x30) >> 4));
      if (outIndex >= outputLength || i >= len) break;

      c1 = ALPHABET.indexOf(encoded.charAt(i++));
      output[outIndex++] = (byte) (((c2 & 0x0F) << 4) | ((c1 & 0x3C) >> 2));
      if (outIndex >= outputLength || i >= len) break;

      c2 = ALPHABET.indexOf(encoded.charAt(i++));
      output[outIndex++] = (byte) (((c1 & 0x03) << 6) | c2);
    }

    return output;
  }

  private String formatHash(String version, int cost, byte[] salt, byte[] hash) {
    String encodedSalt = bcryptBase64Encode(salt, 16);
    String encodedHash = bcryptBase64Encode(hash, 23);
    return String.format("$%s$%02d$%s%s", version, cost, encodedSalt, encodedHash);
  }

  private ParsedHash parseHash(String hashed) {
    if (!hashed.startsWith("$2")) throw new IllegalArgumentException("Invalid bcrypt hash format");
    String[] parts = hashed.split("\\$");
    if (parts.length != 4) throw new IllegalArgumentException("Invalid bcrypt hash format");
    String version = parts[1];
    int cost = Integer.parseInt(parts[2]);
    String saltHash = parts[3];
    byte[] salt = decodeBase64(saltHash.substring(0, 22), SALT_BYTES);
    return new ParsedHash(version, cost, salt);
  }

  private byte[] toNullTerminated(byte[] password) {
    byte[] result = new byte[password.length + 1];
    System.arraycopy(password, 0, result, 0, password.length);
    result[password.length] = 0x00;
    return result;
  }

  private boolean constantTimeEquals(String a, String b) {
    // CVE-2023-20861: timing-safe comparison prevents timing attacks
    byte[] aBytes = a.getBytes();
    byte[] bBytes = b.getBytes();
    if (aBytes.length != bBytes.length) return false;
    int result = 0;
    for (int i = 0; i < aBytes.length; i++) {
      result |= aBytes[i] ^ bBytes[i];
    }
    return result == 0;
  }

  private int[] extractP(int[] state) {
    int[] p = new int[18];
    System.arraycopy(state, 0, p, 0, 18);
    return p;
  }

  private int[][] extractS(int[] state) {
    int[][] s = new int[4][256];
    for (int i = 0; i < 4; i++) {
      System.arraycopy(state, 18 + i * 256, s[i], 0, 256);
    }
    return s;
  }
}
