package twoauth.backend.security.controller;

import twoauth.backend.exception.BadRequestException;
import twoauth.backend.security.Validator;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.JwtResponse;
import twoauth.backend.security.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import twoauth.backend.security.service.LoginService;
import twoauth.backend.security.service.registration.RegistrationService;

@RestController
@RequiredArgsConstructor
public class AuthenticationController
{
    private final RegistrationService registrationService;
    private final LoginService loginService;

    @PostMapping("/registration")
    public Object registration(@RequestBody final User.RegistrationDto user)
    {
        String errorMessage;
        if ((errorMessage = Validator.validateUserRegistrationDto(user)) != null)
            throw new BadRequestException(errorMessage);

        if (! registrationService.registration(user))
            throw new BadRequestException("User not registered.");

        return ResponseEntity.ok(null);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody final AuthRequest request)
    {
        String errorMessage;
        if ((errorMessage = Validator.validateAuthRequest(request)) != null)
            throw new BadRequestException(errorMessage);

        return loginService.login(request);
    }
}
