package twoauth.backend.exception;

public class InvalidDbEntityException extends RuntimeException {
    public InvalidDbEntityException(String message) {
        super(message);
    }
}
