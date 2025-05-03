package twoauth.apigateway.model;

import org.springframework.security.core.CredentialsContainer;

import java.util.List;

public final class User implements CredentialsContainer
{
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private List<String> permissions;

    private User() {}

    @Override
    public void eraseCredentials() {
        this.password = null;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getFirstName() {
        return firstName;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public String getLastName() {
        return lastName;
    }

    @Override
    public String toString() {
        return "User{" +
                "email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", permissions=" + permissions +
                '}';
    }
}
