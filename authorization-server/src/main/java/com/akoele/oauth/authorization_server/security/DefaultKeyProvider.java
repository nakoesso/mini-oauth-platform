package com.akoele.oauth.authorization_server.security;


import com.akoele.oauth.authorization_server.crypto.SigningKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class DefaultKeyProvider implements KeyProvider {
    private final Map<String, SigningKey> signingKeys;
    private final String activeKid;

    public DefaultKeyProvider(
            List<SigningKey> signingKeys,
            @Value("${jwt.active-key}") String activeKid) {

        this.activeKid = activeKid;

        this.signingKeys = signingKeys.stream()
                .collect(Collectors.toMap(
                        SigningKey::kid,
                        Function.identity(),
                        (existing, replacement) -> {
                            throw new IllegalStateException(
                                    "Clé en double détectée pour le kid : " + existing.kid()
                            );
                        }
                ));
    }

    @Override
    public SigningKey getActiveKey() {
        SigningKey signingKey = signingKeys.get(activeKid);

        if (signingKey == null) {
            throw new IllegalStateException(
                    "Aucune clé configurée avec le kid : " + activeKid
            );
        }

        return signingKey;
    }
}
