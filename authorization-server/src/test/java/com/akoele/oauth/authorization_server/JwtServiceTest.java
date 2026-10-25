package com.akoele.oauth.authorization_server;

import com.akoele.oauth.authorization_server.crypto.SigningKey;
import com.akoele.oauth.authorization_server.security.KeyProvider;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtServiceTest {
    private JwtService jwtService;

    private RSAPublicKey publicKey;

    private KeyProvider keyProvider;

    private final String testIssuer = "test-oauth-platform";

    private final String activeKid = "key-1";

    @BeforeEach
    void setUp() {

        KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();

        RSAPrivateKey privateKey =
                (RSAPrivateKey) keyPair.getPrivate();

        publicKey =
                (RSAPublicKey) keyPair.getPublic();

        SigningKey signingKey =
                new SigningKey(
                        activeKid,
                        privateKey,
                        publicKey
                );

        keyProvider = mock(KeyProvider.class);

        when(keyProvider.getActiveKey())
                .thenReturn(signingKey);

        jwtService = new JwtService(
                keyProvider,
                testIssuer
        );
    }

    @Test
    void generateToken_returnsNonEmptyToken() {

        String token = jwtService.generateToken("user-123");

        assertNotNull(token, "Le token ne doit pas être null");

        assertFalse(
                token.trim().isEmpty(),
                "Le token ne doit pas être vide"
        );
    }

    @Test
    void generateToken_containsExpectedClaims() {

        String subject = "akoele";

        Instant beforeGeneration = Instant.now();

        String token = jwtService.generateToken(subject);

        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(
                subject,
                claims.getSubject(),
                "Le subject (sub) ne correspond pas"
        );

        assertEquals(
                testIssuer,
                claims.getIssuer(),
                "Le claim iss ne correspond pas"
        );

        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();

        assertNotNull(
                issuedAt,
                "Le claim iat doit être présent"
        );

        assertNotNull(
                expiration,
                "Le claim exp doit être présent"
        );

        assertTrue(
                expiration.after(issuedAt),
                "exp doit être postérieur à iat"
        );

        assertTrue(
                expiration.toInstant().isAfter(beforeGeneration),
                "exp doit être dans le futur"
        );
    }

    @Test
    void generateToken_containsExpectedKidInHeader() throws Exception {

        String token = jwtService.generateToken("akoele");

        String[] parts = token.split("\\.");

        String encodedHeader = parts[0];

        String headerJson = new String(
                Base64.getUrlDecoder().decode(encodedHeader),
                StandardCharsets.UTF_8
        );

        ObjectMapper objectMapper = new ObjectMapper();

        JsonNode header =
                objectMapper.readTree(headerJson);

        // Vérification du Key ID (kid) actif
        assertEquals(
                activeKid,
                header.get("kid").asText()
        );

        // Vérification de l'algorithme de signature (alg)
        assertEquals(
                "RS256",
                header.get("alg").asText()
        );
    }

    @Test
    void generateToken_signatureCanBeVerifiedWithPublicKey() {

        String token = jwtService.generateToken("akoele");

        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals(
                "akoele",
                claims.getSubject()
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ",
            "   ",
            "\t",
            "\n"
    })
    void generateToken_throwsWhenSubjectIsNullOrBlank(
            String invalidSubject) {

        assertThrows(
                IllegalArgumentException.class,
                () -> jwtService.generateToken(invalidSubject),
                "Une IllegalArgumentException était attendue"
        );
    }
}
