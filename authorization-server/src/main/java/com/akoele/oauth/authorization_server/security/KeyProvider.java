package com.akoele.oauth.authorization_server.security;

import com.akoele.oauth.authorization_server.crypto.SigningKey;

public interface KeyProvider {

    SigningKey getActiveKey();
}
