package twoauth.backend.security;

public class UserNotDeletedException extends Exception {
    public UserNotDeletedException(String message) {
        super(message);
    }
}
