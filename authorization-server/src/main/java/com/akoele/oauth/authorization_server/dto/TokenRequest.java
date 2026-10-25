package com.akoele.oauth.authorization_server.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenRequest(
        @NotBlank(message = "Le champ subject est obligatoire") String subject
) {
}
