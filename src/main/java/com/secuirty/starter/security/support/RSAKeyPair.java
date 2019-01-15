package com.secuirty.starter.security.support;

import lombok.Builder;
import lombok.Data;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Data
@Builder
public class RSAKeyPair {

    private RSAPrivateKey privateKey;

    private RSAPublicKey publicKey;


}
