package com.noxto.springsecuritydemo.utils;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
public class RSAKeyGenerator {

    public static KeyPair generateRSAKey() {
        KeyPair keyPair;
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return keyPair;
    }

}
