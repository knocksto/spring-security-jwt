package com.noxto.springsecuritydemo.utils;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
@Getter
@Setter
public class RSAKeyProperties {
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;
    public RSAKeyProperties(){
        KeyPair keyPair = RSAKeyGenerator.generateRSAKey();
        rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    }
}
