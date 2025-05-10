package twoauth.backend.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;
import java.util.List;

@Getter
@ToString
public final class User implements UserDetails, CredentialsContainer
{
    public record SecureDto(
            @Id
            String email,
            String firstName,
            String lastName,
            Date creation,
            Date lastUpdate,
            List<String> permissions,
            boolean isActive
    ) {}

    @Getter
    @ToString
    public static class RegistrationDto implements CredentialsContainer
    {
        @Id
        private String email;
        @ToString.Exclude
        private String password;
        private String firstName;
        private String lastName;
        private List<String> permissions;

        private RegistrationDto() {}

        @Override
        public void eraseCredentials() {
            this.password = null;
        }
    }

    @Id
    private String email;
    @JsonIgnore
    @ToString.Exclude
    private transient String password;
    private String firstName;
    private String lastName;
    private Date creation;
    private Date lastUpdate;
    private List<SimpleGrantedAuthority> permissions;
    private boolean isActive;
    @JsonIgnore
    @ToString.Exclude
    private transient String activationToken;

    private User() {}

    public User(
            String email, String password, String firstName, String lastName, Date creation,
            Date lastUpdate, List<String> permissions, boolean isActive, String activationToken
    ) {
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.creation = (Date) creation.clone();
        this.lastUpdate = (Date) lastUpdate.clone();
        this.permissions = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .toList(); // Unmodifiable List
        this.isActive = isActive;
        this.activationToken = activationToken;
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    public Date getCreation() {
        if (creation == null)
            return null;
        return (Date) creation.clone();
    }

    public Date getLastUpdate() {
        if (lastUpdate == null)
            return null;
        return (Date) lastUpdate.clone();
    }
}
