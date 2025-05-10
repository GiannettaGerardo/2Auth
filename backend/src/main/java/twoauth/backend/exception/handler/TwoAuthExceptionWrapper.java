package twoauth.backend.exception.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

@Getter
public class TwoAuthExceptionWrapper
{
    private final int status;
    private final ZonedDateTime timestamp;
    private final String error;

    public TwoAuthExceptionWrapper(
            String error,
            HttpStatus httpStatus,
            ZonedDateTime timestamp
    ) {
        this.status = httpStatus.value();
        this.timestamp = timestamp;
        this.error = error;
    }
}
