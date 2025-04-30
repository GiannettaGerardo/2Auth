package twoauth.backend.security.controller;

import twoauth.backend.security.UserNotSavedException;
import twoauth.backend.security.Validator;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.User;
import twoauth.backend.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthenticationController
{
    private final AuthenticationService authenticationService;

    @PostMapping("/registration")
    public ResponseEntity<String> registration(@RequestBody final User user) throws UserNotSavedException
    {
        String errorMessage;
        if ((errorMessage = Validator.validateUser(user, false)) != null)
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST.value())
                    .body(errorMessage);

        return authenticationService.registration(user);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody final AuthRequest request)
    {
        String errorMessage;
        if ((errorMessage = Validator.validateAuthRequest(request)) != null)
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST.value())
                    .body(errorMessage);

        return authenticationService.login(request);
    }
}
