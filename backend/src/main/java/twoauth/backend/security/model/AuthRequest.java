package twoauth.backend.security.model;

import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

@Getter
public class AuthRequest implements CredentialsContainer, Externalizable
{
    private String username;
    private String password;

    private AuthRequest() {}

    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        throw new IllegalAccessError();
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        throw new IllegalAccessError();
    }
}