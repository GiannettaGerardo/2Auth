package twoauth.backend.security.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.List;

@AllArgsConstructor
@Getter
public final class User implements CredentialsContainer
{
    public record NoPasswordDto(
            @Id String email,
            String firstName,
            String lastName,
            Date creation,
            Date lastUpdate,
            List<String> permissions
    ) {}

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
    public String toString() {
        return "User{" +
                "email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", creation=" + creation +
                ", lastUpdate=" + lastUpdate +
                ", permissions=" + permissions +
                '}';
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
}
