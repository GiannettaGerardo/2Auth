package twoauth.apigateway;

public class AuthBadRequestException extends RuntimeException {
    public AuthBadRequestException(String message) {
        super(message);
    }
}
