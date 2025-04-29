package twoauth.backend.security.controller;

import twoauth.backend.exception.BadRequestException;
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

    @GetMapping("/{email}")
    public User.NoPasswordDto getById(@PathVariable final String email) throws UserNotFoundException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateEmail(email)) != null)
            throw new BadRequestException(errorMessage);

        return userService.safeGetById(email);
    }

    @PostMapping
    public void save(@RequestBody final User user) throws UserNotSavedException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateUser(user, false)) != null)
            throw new BadRequestException(errorMessage);

        userService.save(user);
    }

    @PutMapping
    public void update(@RequestBody final User.NoPasswordDto user) throws UserNotUpdatedException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateUserNoPassword(user)) != null)
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
