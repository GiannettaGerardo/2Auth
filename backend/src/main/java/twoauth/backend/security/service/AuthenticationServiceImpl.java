package twoauth.backend.security.service;

import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.User;
import twoauth.backend.security.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService
{
    private static final long ONE_DAY_IN_MILLIS = 24L * 60L * 60L * 1000L;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder encoder;
    private final UserRepository userRepository;
    private final JwtKeyStore keyStore;

    @Override
    public ResponseEntity<String> registration(final User user)
    {
        user.encodePassword(encoder);

        if (! userRepository.save(user)) {
            System.err.printf("Cannot save user %s in the database.%n", user.getEmail());
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED.value())
                    .build();
        }
        return ResponseEntity.ok(user.getEmail());
    }

    @Override
    public ResponseEntity<String> login(final AuthRequest request)
    {
        final var authRequest = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
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
                .expiration(new Date(nowInMillis + ONE_DAY_IN_MILLIS))
                .claim("permissions", userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .signWith(keyStore.getKey())
                .compact();

        return ResponseEntity.ok(jws);
    }
}
