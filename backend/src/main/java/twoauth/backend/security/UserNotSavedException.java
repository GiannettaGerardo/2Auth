package twoauth.backend.security;

public class UserNotSavedException extends Exception {
    public UserNotSavedException(String username) {
        super(String.format("User %s not saved.", username));
    }
}
