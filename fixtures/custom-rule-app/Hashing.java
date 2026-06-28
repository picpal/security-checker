package com.example;

import java.security.SecureRandom;

public class Hashing {
    // 양성: 고정 salt (리터럴 getBytes + 고정 base64)
    private static final byte[] SALT = "fixed-salt-value".getBytes();
    private static final String SALT_B64 = "AAAAAAAAAAAAAAAAAAAAAA==";

    // 음성: SecureRandom 계정별 salt (리터럴 아님 → 미탐이어야)
    public byte[] freshSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}
