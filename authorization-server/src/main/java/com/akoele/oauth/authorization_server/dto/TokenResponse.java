package com.akoele.oauth.authorization_server.dto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        Long expiresIn
) {
}
