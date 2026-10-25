package com.akoele.oauth.authorization_server.config;

import com.akoele.oauth.authorization_server.crypto.SigningKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    @Bean
    public SigningKey key1() {
        return loadSigningKey(
                "key-1",
                "keys/key-1-private.pem",
                "keys/key-1-public.pem"
        );
    }

    @Bean
    public SigningKey key2() {
        return loadSigningKey(
                "key-2",
                "keys/key-2-private.pem",
                "keys/key-2-public.pem"
        );
    }

    private SigningKey loadSigningKey(
            String kid,
            String privateKeyPath,
            String publicKeyPath) {

        RSAPrivateKey privateKey = loadPrivateKey(privateKeyPath);
        RSAPublicKey publicKey = loadPublicKey(publicKeyPath);

        return new SigningKey(
                kid,
                privateKey,
                publicKey
        );
    }

    private RSAPrivateKey loadPrivateKey(String privateKeyPath) {
        byte[] decodedBytes = loadAndDecodePem(privateKeyPath);
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to generate RSA private key from path: " + privateKeyPath, e);
        }
    }

    private RSAPublicKey loadPublicKey(String publicKeyPath) {
        byte[] decodedBytes = loadAndDecodePem(publicKeyPath);
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to generate RSA public key from path: " + publicKeyPath, e);
        }
    }

    /**
     * Lit un PEM depuis le classpath et retourne les données décodées Base64.
     */
    private byte[] loadAndDecodePem(String classpathLocation) {
        ClassPathResource resource = new ClassPathResource(classpathLocation);

        // Utilisation d'un try-with-resources pour fermer automatiquement l'InputStream
        try (InputStream inputStream = resource.getInputStream()) {
            String pemContent = new String(
                    inputStream.readAllBytes(),
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
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read PEM file from classpath: " + classpathLocation, e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Failed to decode Base64 content for PEM file: " + classpathLocation, e);
        }
    }
}
