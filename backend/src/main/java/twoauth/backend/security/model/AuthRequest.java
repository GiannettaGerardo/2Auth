package twoauth.backend.security.model;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.CredentialsContainer;

@Getter
public final class AuthRequest implements CredentialsContainer
{
    private String email;
    private String password;
    private String base64OTActivationToken;

    private AuthRequest() {}

    @Override
    public void eraseCredentials() {
        this.password = null;
        this.base64OTActivationToken = null;
    }

    @Nullable
    public String getBase64OTActivationToken() {
        return base64OTActivationToken;
    }

    @Override
    public String toString() {
        return "AuthRequest{" +
                "email='" + email + '\'' +
                '}';
    }
}