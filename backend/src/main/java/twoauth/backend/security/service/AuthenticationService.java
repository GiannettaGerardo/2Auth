package twoauth.backend.security.service;

import twoauth.backend.security.UserNotSavedException;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.User;
import org.springframework.http.ResponseEntity;

public interface AuthenticationService
{
    ResponseEntity<String> registration(User user) throws UserNotSavedException;
    ResponseEntity<String> login(AuthRequest request);
}
