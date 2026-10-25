package com.akoele.oauth.authorization_server;


import com.akoele.oauth.authorization_server.controller.TokenController;
import com.akoele.oauth.authorization_server.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@WebMvcTest(TokenController.class)
@AutoConfigureMockMvc(addFilters = false)
public class TokenControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void shouldReturnTokenWhenRequestIsValid() throws Exception {

        when(jwtService.generateToken("Eunice"))
                .thenReturn("fake-jwt");

        mockMvc.perform(post("/createToken/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "subject":"Eunice"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken")
                        .value("fake-jwt"))
                .andExpect(jsonPath("$.tokenType")
                        .value("Bearer"))
                .andExpect(jsonPath("$.expiresIn")
                        .value(3600));
    }

    @Test
    void shouldReturn400WhenSubjectMissing() throws Exception {

        mockMvc.perform(post("/createToken/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldReturn400WhenSubjectBlank() throws Exception {

        mockMvc.perform(post("/createToken/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "subject":""
                                }
                                """))
                .andExpect(status().isBadRequest());
    }
}
