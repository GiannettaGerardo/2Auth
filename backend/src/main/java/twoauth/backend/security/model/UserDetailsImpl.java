package twoauth.backend.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;
import java.util.List;

public final class UserDetailsImpl implements UserDetails, CredentialsContainer
{
    private final String email;
    @JsonIgnore
    private transient String password;
    @Getter private final String firstName;
    @Getter private final String lastName;
    private final Date creation;
    private final Date lastUpdate;
    private final List<GrantedAuthority> permissions;

    public UserDetailsImpl(
            String email, String password, String firstName, String lastName,
            Date creation, Date lastUpdate, List<String> permissions
    ) {
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.creation = (Date) creation.clone();
        this.lastUpdate = (Date) lastUpdate.clone();
        this.permissions = permissions.stream()
                .map(p -> (GrantedAuthority) new SimpleGrantedAuthority(p))
                .toList(); // Unmodifiable List
    }

    public static UserDetailsImpl fromUser(User user) {
        return new UserDetailsImpl(
                user.getEmail(),
                user.getPassword(),
                user.getFirstName(),
                user.getLastName(),
                user.getCreation(),
                user.getLastUpdate(),
                user.getPermissions()
        );
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

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
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

    @Override
    public String toString() {
        return "User{" +
                "email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", creation=" + creation +
                ", lastUpdate=" + lastUpdate +
                ", permissions=" + permissions.stream().map(GrantedAuthority::getAuthority).toList() +
                '}';
    }
}
