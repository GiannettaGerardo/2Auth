package twoauth.backend.security.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

@Service
class InMemoryJwtKeyStore implements JwtKeyStore
{
    @JsonIgnore
    private final AtomicReference<SecretKey> key;
    @JsonIgnore
    private final TaskScheduler taskScheduler;

    public InMemoryJwtKeyStore(
            @Value("${2Auth.jwt.key-time-validity-in-millis:86400000}") long keyTVM,
            TaskScheduler taskScheduler
    ) {
        final long keyTimeValidityInMillis = (keyTVM < 1) ? 86_400_000L : keyTVM;
        this.key = new AtomicReference<>(null);
        this.taskScheduler = taskScheduler;
        this.taskScheduler.scheduleAtFixedRate(
                /* there is no need to use a mutex or a CAS operation because
                   this is the only write operation on the key and is executed
                   only one time, by only one thread, at a fixed rate. */
                () -> this.key.setRelease(generateNewKey()),
                Duration.ofMillis(keyTimeValidityInMillis)
        );
    }

    @Override
    public SecretKey getKey() {
        return key.getAcquire();
    }

    private SecretKey generateNewKey() {
        System.out.println("New Key generated.");
        return Jwts.SIG.HS512.key().build();
    }

    @Override
    public String toString() {
        return "InMemoryJwtKeyStore{}";
    }
}
