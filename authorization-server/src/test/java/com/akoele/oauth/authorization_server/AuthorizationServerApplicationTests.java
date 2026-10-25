package com.akoele.oauth.authorization_server;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest
class AuthorizationServerApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void mainShouldRunSuccessfully() {
		assertDoesNotThrow(() -> AuthorizationServerApplication.main(new String[]{}));
	}

}
