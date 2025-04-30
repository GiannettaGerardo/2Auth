package twoauth.backend.security.service;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class InMemoryJwtKeyStore implements JwtKeyStore
{
    private final long keyTimeValidityInMillis;
    private final AtomicReference<SecretKey> key;

    public InMemoryJwtKeyStore(
            @Value("${2Auth.jwt.key-time-validity-in-millis}") Long keyTVM
    ) {
        this.keyTimeValidityInMillis = (keyTVM == null || keyTVM < 1) ? 86_400_000L : keyTVM;
        this.key = new AtomicReference<>(generateNewKey());
    }

    @Override
    public SecretKey getKey() {
        return key.getAcquire();
    }

    private static SecretKey generateNewKey() {
        return Jwts.SIG.HS256.key().build();
    }
}
