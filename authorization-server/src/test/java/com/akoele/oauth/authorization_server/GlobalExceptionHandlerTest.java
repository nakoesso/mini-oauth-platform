package com.akoele.oauth.authorization_server;

import com.akoele.oauth.authorization_server.dto.ErrorResponse;
import com.akoele.oauth.authorization_server.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler exceptionHandler = new GlobalExceptionHandler();

    @Test
    void handleIllegalArgument_shouldReturnBadRequest() {
        // Given
        IllegalArgumentException ex = new IllegalArgumentException("Argument invalide fourni");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleIllegalArgument(ex);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(400);
        assertThat(response.getBody().error()).isEqualTo("Argument invalide fourni");
        assertThat(response.getBody().timestamp()).isNotNull();
    }

    @Test
    void handleGeneric_shouldReturnInternalServerError() {
        // Given
        Exception ex = new Exception("Erreur technique inattendue");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleGeneric(ex);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(500);
        assertThat(response.getBody().error()).isEqualTo("Erreur interne");
        assertThat(response.getBody().timestamp()).isNotNull();
    }

    @Test
    void handleValidation_shouldReturnBadRequest_withFieldError() {
        // Given
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError = new FieldError("objectName", "email", "Le format de l'email est invalide");

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of(fieldError));

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleValidation(ex);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(400);
        assertThat(response.getBody().error()).isEqualTo("Le format de l'email est invalide");
    }

    @Test
    void handleValidation_shouldReturnDefaultMessage_whenNoFieldError() {
        // Given
        MethodArgumentNotValidException ex = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);

        when(ex.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(List.of()); // Liste vide pour tester le .orElse("Requête invalide")

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleValidation(ex);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo(400);
        assertThat(response.getBody().error()).isEqualTo("Requête invalide");
    }
}
