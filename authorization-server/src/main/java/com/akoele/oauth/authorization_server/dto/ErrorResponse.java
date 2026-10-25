package com.akoele.oauth.authorization_server.dto;

import java.time.Instant;

public record ErrorResponse(
        Instant timestamp,
        int status,
        String error
) {
}
