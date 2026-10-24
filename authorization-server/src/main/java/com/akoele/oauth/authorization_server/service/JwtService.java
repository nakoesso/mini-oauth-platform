package com.akoele.oauth.authorization_server.service;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {
    private final RSAPrivateKey privateKey;
    private final String issuer;

    public JwtService(RSAPrivateKey privateKey, @Value("${jwt.issuer:mini-oauth-platform}") String issuer) {
        this.privateKey = privateKey;
        this.issuer = issuer;
    }

    /**
     * Génère un JWT signé avec la clé privée RSA.
     *
     * @param subject Le sujet du token (ex: l'identifiant de l'utilisateur / username)
     * @return Le token JWT sous forme de chaîne de caractères (String)
     */
    public String generateToken(String subject){

        if (subject == null || subject.trim().isEmpty()) {
            throw new IllegalArgumentException("Le subject (sujet) du token ne peut pas être null ou vide.");
        }
        Instant now = Instant.now();

        Instant expiration = now.plusSeconds(3600); // 1 heure de validité

        return Jwts.builder()
                .issuer(issuer)
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }
}
