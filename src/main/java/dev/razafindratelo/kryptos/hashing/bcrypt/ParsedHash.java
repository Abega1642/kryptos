package dev.razafindratelo.kryptos.hashing.bcrypt;

public record ParsedHash(String version, int cost, byte[] salt) {}
