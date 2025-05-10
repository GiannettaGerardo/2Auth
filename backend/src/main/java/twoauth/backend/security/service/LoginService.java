package twoauth.backend.security.service;

import org.springframework.http.ResponseEntity;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.JwtResponse;

public interface LoginService {
    ResponseEntity<JwtResponse> login(AuthRequest request);
}
