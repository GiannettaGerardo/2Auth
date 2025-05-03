package twoauth.backend.security.model;

import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;

@Getter
public final class AuthRequest implements CredentialsContainer
{
    private String email;
    private String password;

    private AuthRequest() {}

    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    @Override
    public String toString() {
        return "AuthRequest{" +
                "email='" + email + '\'' +
                '}';
    }
}