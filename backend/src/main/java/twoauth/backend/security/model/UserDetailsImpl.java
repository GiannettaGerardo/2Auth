package twoauth.backend.security.model;

import lombok.Getter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Collection;
import java.util.Date;
import java.util.List;

public class UserDetailsImpl implements UserDetails, CredentialsContainer, Externalizable
{
    private String email;
    private String password;
    @Getter private String firstName;
    @Getter private String lastName;
    private Date creation;
    private Date lastUpdate;
    private List<GrantedAuthority> permissions;

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

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        throw new IllegalAccessError();
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        throw new IllegalAccessError();
    }
}
