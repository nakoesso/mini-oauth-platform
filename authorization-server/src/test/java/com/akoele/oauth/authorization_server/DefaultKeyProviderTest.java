package com.akoele.oauth.authorization_server;

import com.akoele.oauth.authorization_server.crypto.SigningKey;
import com.akoele.oauth.authorization_server.security.DefaultKeyProvider;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

public class DefaultKeyProviderTest {

    @Test
    void shouldReturnActiveKey() {

        SigningKey key1 = new SigningKey(
                "key-1",
                mock(RSAPrivateKey.class),
                mock(RSAPublicKey.class)
        );

        SigningKey key2 = new SigningKey(
                "key-2",
                mock(RSAPrivateKey.class),
                mock(RSAPublicKey.class)
        );

        DefaultKeyProvider provider =
                new DefaultKeyProvider(
                        List.of(key1, key2),
                        "key-1"
                );

        SigningKey activeKey = provider.getActiveKey();

        assertEquals("key-1", activeKey.kid());
        assertSame(key1, activeKey);
    }

    @Test
    void shouldReturnSecondKeyWhenConfiguredAsActive() {

        SigningKey key1 = new SigningKey(
                "key-1",
                mock(RSAPrivateKey.class),
                mock(RSAPublicKey.class)
        );

        SigningKey key2 = new SigningKey(
                "key-2",
                mock(RSAPrivateKey.class),
                mock(RSAPublicKey.class)
        );

        DefaultKeyProvider provider =
                new DefaultKeyProvider(
                        List.of(key1, key2),
                        "key-2"
                );

        SigningKey activeKey = provider.getActiveKey();

        assertEquals("key-2", activeKey.kid());
        assertSame(key2, activeKey);
    }

    @Test
    void shouldThrowExceptionWhenActiveKeyDoesNotExist() {

        SigningKey key1 = new SigningKey(
                "key-1",
                mock(RSAPrivateKey.class),
                mock(RSAPublicKey.class)
        );

        DefaultKeyProvider provider =
                new DefaultKeyProvider(
                        List.of(key1),
                        "unknown-key"
                );

        IllegalStateException exception =
                assertThrows(
                        IllegalStateException.class,
                        provider::getActiveKey
                );

        assertTrue(
                exception.getMessage()
                        .contains("unknown-key")
        );
    }

    @Test
    void shouldThrowExceptionWhenNoKeyMatchesConfiguredKid() {

        DefaultKeyProvider provider =
                new DefaultKeyProvider(
                        List.of(),
                        "key-1"
                );

        assertThrows(
                IllegalStateException.class,
                provider::getActiveKey
        );
    }
}
