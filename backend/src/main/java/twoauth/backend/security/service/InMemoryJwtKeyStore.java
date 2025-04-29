package twoauth.backend.security.service;

import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class InMemoryJwtKeyStore implements JwtKeyStore
{
    private final AtomicReference<SecretKey> key = new AtomicReference<>(generateNewKey());

    @Override
    public SecretKey getKey() {
        return key.getAcquire();
    }

    private static SecretKey generateNewKey() {
        return Jwts.SIG.HS256.key().build();
    }
}
