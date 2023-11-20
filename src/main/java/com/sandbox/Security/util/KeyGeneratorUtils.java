package com.sandbox.Security.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class KeyGeneratorUtils {
    public static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex){
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
