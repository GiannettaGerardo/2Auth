package twoauth.backend.exception.handler;

import twoauth.backend.exception.BadRequestException;
import twoauth.backend.exception.InvalidDbEntityException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import twoauth.backend.exception.UserNotDeletedException;
import twoauth.backend.exception.UserNotFoundException;
import twoauth.backend.exception.UserNotUpdatedException;

import java.time.ZoneId;
import java.time.ZonedDateTime;

@ControllerAdvice
public class TwoAuthExceptionHandler
{
    private static final ZonedDateTime ZONE = ZonedDateTime.now(ZoneId.of("Europe/Rome"));

    @ExceptionHandler(value = {
            BadRequestException.class,
            UserNotFoundException.class,
            UserNotDeletedException.class,
            UserNotUpdatedException.class
    })
    public ResponseEntity<TwoAuthExceptionWrapper> handleBadRequestException(Exception e)
    {
        final HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new TwoAuthExceptionWrapper(e.getMessage(), httpStatus, ZONE), httpStatus);
    }

    @ExceptionHandler(value = {InvalidDbEntityException.class})
    public ResponseEntity<TwoAuthExceptionWrapper> handleInvalidDbEntityException(InvalidDbEntityException e)
    {
        final HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        return new ResponseEntity<>(new TwoAuthExceptionWrapper("Something went wrong.", httpStatus, ZONE), httpStatus);
    }
}
