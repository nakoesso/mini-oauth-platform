package com.akoele.oauth.authorization_server;

import com.akoele.oauth.authorization_server.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class JwtServiceTest {
    private JwtService jwtService;
    private RSAPublicKey publicKey;
    private final String testIssuer = "test-oauth-platform";

    @BeforeEach
    void setUp() {
        // 1. Génération d'une paire de clés RSA en mémoire pour les tests
        KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        // 2. Instanciation directe du service avec ces paramètres de test
        jwtService = new JwtService(privateKey, testIssuer);
    }

    @Test
    void generateToken_returnsNonEmptyToken() {
        String token = jwtService.generateToken("user-123");

        assertNotNull(token, "Le token ne doit pas être null");
        assertFalse(token.trim().isEmpty(), "Le token ne doit pas être vide");
    }

    @Test
    void generateToken_containsExpectedClaims() {
        String subject = "john.doe";

        // Capturer l'instant juste avant la génération pour comparer l'expiration
        Instant beforeGeneration = Instant.now();

        String token = jwtService.generateToken(subject);

        // Parsing et vérification de la signature + extraction du payload
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // Vérifications des claims demandés
        assertEquals(subject, claims.getSubject(), "Le subject (sub) ne correspond pas");
        assertEquals(testIssuer, claims.getIssuer(), "L'émetteur (iss) ne correspond pas");

        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();

        assertNotNull(issuedAt, "Le claim iat (Issued At) doit être présent");
        assertNotNull(expiration, "Le claim exp (Expiration) doit être présent");

        // Vérifications temporelles robustes
        assertTrue(expiration.after(issuedAt), "La date d'expiration (exp) doit être postérieure à iat");
        assertTrue(expiration.toInstant().isAfter(beforeGeneration), "La date d'expiration (exp) doit être dans le futur par rapport à l'heure actuelle");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    void generateToken_throwsWhenSubjectIsNullOrBlank(String invalidSubject) {
        assertThrows(IllegalArgumentException.class, () -> {
            jwtService.generateToken(invalidSubject);
        }, "Une exception IllegalArgumentException était attendue pour un subject vide ou null");
    }

}
