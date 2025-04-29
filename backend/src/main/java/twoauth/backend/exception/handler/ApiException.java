package twoauth.backend.exception.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

@Getter
public class ApiException extends AbstractApiException
{
    private final String error;

    public ApiException(
            String error,
            HttpStatus httpStatus,
            ZonedDateTime timestamp
    ) {
        super(httpStatus, timestamp);
        this.error = error;
    }
}
