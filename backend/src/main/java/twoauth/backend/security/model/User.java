package twoauth.backend.security.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Date;
import java.util.List;

@AllArgsConstructor
@Getter
public final class User implements CredentialsContainer, Externalizable
{
    @Id private String email;
    private String password;
    private String firstName;
    private String lastName;
    @Setter private Date creation;
    @Setter private Date lastUpdate;
    private List<String> permissions;

    private User() {}

    public void encodePassword(PasswordEncoder encoder) {
        password = encoder.encode(password);
    }

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

    public record NoPasswordDto(
            @Id String email,
            String firstName,
            String lastName,
            Date creation,
            Date lastUpdate,
            List<String> permissions
    ) {}
}
