package twoauth.backend.security.service;

import org.springframework.beans.factory.annotation.Value;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.User;
import twoauth.backend.security.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthenticationServiceImpl implements AuthenticationService
{
    private final long jwtTimeValidityInMillis;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder encoder;
    private final UserRepository userRepository;
    private final JwtKeyStore keyStore;

    public AuthenticationServiceImpl(
            @Value("${2Auth.jwt.time-validity-in-millis}") Long jwtTVM,
            final AuthenticationManager authenticationManager,
            final PasswordEncoder encoder,
            final UserRepository userRepository,
            final JwtKeyStore keyStore
    ) {
        this.jwtTimeValidityInMillis = (jwtTVM == null || jwtTVM < 1) ? 28_800_000L : jwtTVM;
        this.authenticationManager = authenticationManager;
        this.encoder = encoder;
        this.userRepository = userRepository;
        this.keyStore = keyStore;
    }

    @Override
    public ResponseEntity<String> registration(final User user)
    {
        user.encodePassword(encoder);

        if (! userRepository.save(user)) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST.value())
                    .body("User not registered.");
        }
        return ResponseEntity.ok(user.getEmail());
    }

    @Override
    public ResponseEntity<String> login(final AuthRequest request)
    {
        final var authRequest = new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());
        request.eraseCredentials();

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(authRequest);
        }
        catch (AuthenticationException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .build();
        }

        var userDetails = (UserDetails) authentication.getPrincipal();

        final long nowInMillis = System.currentTimeMillis();
        final String jws = Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(nowInMillis))
                .expiration(new Date(nowInMillis + jwtTimeValidityInMillis))
                .claim("permissions", userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .signWith(keyStore.getKey())
                .compact();

        return ResponseEntity.ok(jws);
    }
}
