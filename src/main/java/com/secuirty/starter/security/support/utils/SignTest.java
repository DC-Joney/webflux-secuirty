package com.secuirty.starter.security.support.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class SignTest {
    public static void main(String[] args) throws ParseException, NoSuchAlgorithmException, JOSEException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        JWTClaimsSet joe = builder.subject("joe")
                .expirationTime(Date.from(Instant.now().plus(Duration.ofSeconds(20))))
                .claim("http://example.com/is_root", true)
                .build();


        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
                contentType("text/plain").
                customParam("exp", new Date().getTime()).
                build();



        SignedJWT signedJWT = new SignedJWT(header,joe);



        //实例化密钥生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //初始化密钥生成器
        keyPairGenerator.initialize(1024);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //甲方公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        //甲方私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSASSASigner rsassaSigner = new RSASSASigner(privateKey);

        signedJWT.sign(rsassaSigner);

        System.out.println(signedJWT.serialize());

        ReactiveJwtDecoder jwtDecoder = new NimbusReactiveJwtDecoder(publicKey);

        Mono<Jwt> decode = jwtDecoder.decode(signedJWT.serialize());

        decode.subscribe(jwt->{
            System.out.println(jwt.getHeaders());
            System.out.println(jwt.getTokenValue());
            System.out.println(jwt.getClaims());
        });


    }
}
