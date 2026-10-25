package com.akoele.oauth.authorization_server.service;

import com.akoele.oauth.authorization_server.crypto.SigningKey;
import com.akoele.oauth.authorization_server.security.KeyProvider;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {
    private final KeyProvider keyProvider;
    private final String issuer;

    public JwtService(
            KeyProvider keyProvider,
            @Value("${jwt.issuer:mini-oauth-platform}") String issuer) {

        this.keyProvider = keyProvider;
        this.issuer = issuer;
    }

    /**
     * Génère un JWT signé avec la clé privée RSA active.
     *
     * @param subject le sujet du token
     * @return le JWT signé
     */
    public String generateToken(String subject) {

        if (subject == null || subject.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "Le subject (sujet) du token ne peut pas être null ou vide."
            );
        }

        SigningKey activeKey = keyProvider.getActiveKey();

        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);

        return Jwts.builder()

                // Header JWT
                .header()
                .keyId(activeKey.kid())
                .and()

                // Claims
                .issuer(issuer)
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))

                // Signature
                .signWith(
                        activeKey.privateKey(),
                        Jwts.SIG.RS256
                )

                .compact();
    }
}
