package twoauth.apigateway.model;

import org.springframework.security.core.CredentialsContainer;

public final class AuthRequest implements CredentialsContainer {
    private String email;
    private String password;

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
