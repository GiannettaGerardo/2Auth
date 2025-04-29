package twoauth.backend.exception.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

@Getter
public abstract class AbstractApiException
{
    private final int status;
    private final ZonedDateTime timestamp;

    protected AbstractApiException(
            HttpStatus httpStatus,
            ZonedDateTime timestamp
    ) {
        this.status = httpStatus.value();
        this.timestamp = timestamp;
    }
}
