package twoauth.apigateway.model;

import org.springframework.security.core.CredentialsContainer;

import java.io.Serializable;

public final class AuthRequest implements CredentialsContainer, Serializable {
    private String email;
    private transient String password;

    private AuthRequest() {}

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

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
