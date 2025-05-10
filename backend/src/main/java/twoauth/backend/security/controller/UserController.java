package twoauth.backend.security.controller;

import org.springframework.http.MediaType;
import twoauth.backend.exception.BadRequestException;
import twoauth.backend.exception.UserNotDeletedException;
import twoauth.backend.exception.UserNotFoundException;
import twoauth.backend.exception.UserNotUpdatedException;
import twoauth.backend.security.*;
import twoauth.backend.security.model.User;
import twoauth.backend.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController
{
    private final UserService userService;

    @GetMapping(value = "/{email}", produces = MediaType.APPLICATION_JSON_VALUE)
    public User.SecureDto getById(@PathVariable final String email) throws UserNotFoundException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateEmail(email)) != null)
            throw new BadRequestException(errorMessage);

        return userService.safeGetById(email);
    }

    @PutMapping
    public void update(@RequestBody final User.SecureDto user) throws UserNotUpdatedException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateUserSecureDto(user)) != null)
            throw new BadRequestException(errorMessage);

        userService.update(user);
    }

    @DeleteMapping("/{email}")
    public void delete(@PathVariable final String email) throws UserNotDeletedException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateEmail(email)) != null)
            throw new BadRequestException(errorMessage);

        userService.delete(email);
    }
}
