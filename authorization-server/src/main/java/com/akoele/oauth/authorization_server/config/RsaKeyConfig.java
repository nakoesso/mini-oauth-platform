package com.akoele.oauth.authorization_server.config;

import com.akoele.oauth.authorization_server.crypto.SigningKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    @Bean
    public SigningKey key1() throws Exception {
        return loadSigningKey(
                "key-1",
                "keys/key-1-private.pem",
                "keys/key-1-public.pem"
        );
    }

    @Bean
    public SigningKey key2() throws Exception {
        return loadSigningKey(
                "key-2",
                "keys/key-2-private.pem",
                "keys/key-2-public.pem"
        );
    }

    private SigningKey loadSigningKey(
            String kid,
            String privateKeyPath,
            String publicKeyPath) throws Exception {

        RSAPrivateKey privateKey = loadPrivateKey(privateKeyPath);
        RSAPublicKey publicKey = loadPublicKey(publicKeyPath);

        return new SigningKey(
                kid,
                privateKey,
                publicKey
        );
    }

    private RSAPrivateKey loadPrivateKey(String privateKeyPath)
            throws Exception {

        byte[] decodedBytes = loadAndDecodePem(privateKeyPath);

        PKCS8EncodedKeySpec keySpec =
                new PKCS8EncodedKeySpec(decodedBytes);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private RSAPublicKey loadPublicKey(String publicKeyPath)
            throws Exception {

        byte[] decodedBytes = loadAndDecodePem(publicKeyPath);

        X509EncodedKeySpec keySpec =
                new X509EncodedKeySpec(decodedBytes);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Lit un PEM depuis le classpath et retourne
     * les données décodées Base64.
     */
    private byte[] loadAndDecodePem(String classpathLocation)
            throws Exception {

        ClassPathResource resource =
                new ClassPathResource(classpathLocation);

        String pemContent =
                new String(
                        resource.getInputStream().readAllBytes(),
                        StandardCharsets.UTF_8
                );

        String cleanedPem = pemContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        return Base64.getDecoder().decode(cleanedPem);
    }
}
