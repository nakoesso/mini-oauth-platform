package com.akoele.oauth.authorization_server.crypto;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public record SigningKey(
        String kid,
        RSAPrivateKey privateKey,
        RSAPublicKey publicKey
) {
}
