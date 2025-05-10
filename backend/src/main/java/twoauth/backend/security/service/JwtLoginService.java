package twoauth.backend.security.service;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import twoauth.backend.exception.BadRequestException;
import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.JwtResponse;
import twoauth.backend.security.model.User;
import twoauth.backend.security.repository.UserSecurityRepository;

import java.util.Date;

@Service
class JwtLoginService implements LoginService
{
    private final long jwtTimeValidityInMillis;
    private final AuthenticationManager authenticationManager;
    private final JwtKeyStore keyStore;
    private final UserSecurityRepository userRepository;

    public JwtLoginService(
            @Value("${2Auth.jwt.time-validity-in-millis:28800000}") long jwtTVM,
            final AuthenticationManager authenticationManager,
            final JwtKeyStore keyStore,
            final UserSecurityRepository userRepository
    ) {
        this.jwtTimeValidityInMillis = (jwtTVM < 1) ? 28_800_000L : jwtTVM;
        this.authenticationManager = authenticationManager;
        this.keyStore = keyStore;
        this.userRepository = userRepository;
    }

    @Override
    public final ResponseEntity<JwtResponse> login(final AuthRequest request)
    {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        }
        catch (AuthenticationException e) {
            return eraseCredentialsAndGetUnauthorized(request);
        }

        final User userFromDB = safeCastUser(authentication.getPrincipal());
        if (userFromDB == null) {
            System.err.println("User from Database is deserialized with an incorrect class.");
            return eraseCredentialsAndGetUnauthorized(request);
        }

        if (userFromDB.isActive()) {
            if (request.getBase64OTActivationToken() != null)
                throw new BadRequestException("Activation Token is not necessary.");
        }
        else if (!tryAccountActivation(request, userFromDB))
            return eraseCredentialsAndGetUnauthorized(request);

        request.eraseCredentials();

        final long nowInMillis = System.currentTimeMillis();
        final String jws = Jwts.builder()
                .subject(userFromDB.getUsername())
                .issuedAt(new Date(nowInMillis))
                .expiration(new Date(nowInMillis + jwtTimeValidityInMillis))
                .claim("permissions", userFromDB.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .signWith(keyStore.getKey())
                .compact();

        return ResponseEntity.ok(new JwtResponse(jws));
    }

    private boolean tryAccountActivation(final AuthRequest request, final User userFromDB)
    {
        final String base64OTActivationToken = request.getBase64OTActivationToken();
        if (base64OTActivationToken == null) {
            System.err.println("Not enabled User tried login without an OT Activation Token.");
            return false;
        }

        if (! base64OTActivationToken.equals(userFromDB.getActivationToken())) {
            System.err.println("Not enabled User tried login with an invalid OT Activation Token.");
            return false;
        }

        return userRepository.optimisticLockEnableUserAccount(userFromDB);
    }

    @Nullable
    private static User safeCastUser(final Object obj) {
        return (obj instanceof User user) ? user : null;
    }

    private static ResponseEntity<JwtResponse> eraseCredentialsAndGetUnauthorized(final AuthRequest request) {
        request.eraseCredentials();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value()).build();
    }
}
