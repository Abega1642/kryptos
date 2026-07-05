package dev.razafindratelo.kryptos.encryption.symmetric.block_cypher;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum AESVariant {
  AES_128(16, 10),
  AES_192(24, 12),
  AES_256(32, 14);

  private final int keyBytes;
  private final int rounds;
}
