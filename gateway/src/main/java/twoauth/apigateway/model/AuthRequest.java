package twoauth.apigateway.model;

import org.springframework.security.core.CredentialsContainer;

public final class AuthRequest implements CredentialsContainer {
    private String email;
    private String password;
    private String base64OTActivationToken;

    private AuthRequest() {}

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getBase64OTActivationToken() {
        return base64OTActivationToken;
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
        this.base64OTActivationToken = null;
    }

    @Override
    public String toString() {
        return "AuthRequest{" +
                "email='" + email + '\'' +
                '}';
    }
}
