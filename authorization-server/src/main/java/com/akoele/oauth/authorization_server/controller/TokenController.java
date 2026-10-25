package com.akoele.oauth.authorization_server.controller;

import com.akoele.oauth.authorization_server.dto.TokenRequest;
import com.akoele.oauth.authorization_server.dto.TokenResponse;
import com.akoele.oauth.authorization_server.service.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/createToken")
public class TokenController {
    private final JwtService jwtService;

    public TokenController(JwtService jwtService) {
        this.jwtService = jwtService;
    }
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> token(
            @Valid @RequestBody TokenRequest request) {

        String token = jwtService.generateToken(request.subject());

        TokenResponse response = new TokenResponse(
                token,
                "Bearer",
                3600L
        );

        return ResponseEntity.ok(response);
    }

}
