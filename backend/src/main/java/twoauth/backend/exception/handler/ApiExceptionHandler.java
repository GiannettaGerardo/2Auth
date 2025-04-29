package twoauth.backend.exception.handler;

import twoauth.backend.exception.BadRequestException;
import twoauth.backend.exception.InvalidDbEntityException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.ZoneId;
import java.time.ZonedDateTime;

@ControllerAdvice
public class ApiExceptionHandler
{
    private static final ZonedDateTime ZONE = ZonedDateTime.now(ZoneId.of("Europe/Rome"));

    @ExceptionHandler(value = {BadRequestException.class})
    public ResponseEntity<ApiException> handleBadRequestException(BadRequestException e)
    {
        final HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
        return new ResponseEntity<>(new ApiException(e.getMessage(), httpStatus, ZONE), httpStatus);
    }

    @ExceptionHandler(value = {InvalidDbEntityException.class})
    public ResponseEntity<ApiException> handleInvalidDbEntityException(InvalidDbEntityException e)
    {
        final HttpStatus httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        return new ResponseEntity<>(new ApiException("Something went wrong.", httpStatus, ZONE), httpStatus);
    }
}
