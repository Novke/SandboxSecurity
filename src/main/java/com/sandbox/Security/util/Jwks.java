package com.sandbox.Security.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.KeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Jwks {

    public static RSAKey generateRsa() {
        KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.err.println("\n\nKeys:\nPublic: " + publicKey + "\nPrivate: " + privateKey + "\n");

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
}
