package twoauth.backend.exception;

public class UserNotFoundException extends Exception {
    public UserNotFoundException(String username) {
        super(String.format("User %s not found.", username));
    }
}
