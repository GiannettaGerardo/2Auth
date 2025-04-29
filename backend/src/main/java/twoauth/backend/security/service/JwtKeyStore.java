package twoauth.backend.security.service;

import javax.crypto.SecretKey;

public interface JwtKeyStore
{
    SecretKey getKey();
}
