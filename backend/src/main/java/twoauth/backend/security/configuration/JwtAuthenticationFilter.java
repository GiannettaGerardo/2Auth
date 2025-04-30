package twoauth.backend.security.configuration;

import twoauth.backend.security.service.JwtKeyStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter
{
    private static final List<String> EXCLUSION_URIS = List.of("/login", "/registration");
    private final JwtKeyStore keyStore;

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return EXCLUSION_URIS.contains(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain filterChain
    ) throws ServletException, IOException
    {
        String jws;
        if ((jws = getJwsFromRequest(request)) == null) {
            filterChain.doFilter(request, response);
            return;
        }

        Claims payload;
        try {
            payload = Jwts.parser()
                    .verifyWith(keyStore.getKey())
                    .build()
                    .parseSignedClaims(jws)
                    .getPayload();
        }
        catch (JwtException e) {
            // don't trust the JWT!
            filterChain.doFilter(request, response);
            return;
        }

        if (isJwsExpired(payload.getExpiration())) {
            // don't trust the JWT!
            filterChain.doFilter(request, response);
            return;
        }

        final String subject = payload.getSubject();
        final var permissions = (ArrayList<String>) payload.get("permissions");

        System.out.println("Autenticato utente " + subject);
        permissions.forEach(System.out::println);
        System.out.println();

        final var authToken = new UsernamePasswordAuthenticationToken(
                subject,
                null,
                permissions.stream()
                        .map(p -> (GrantedAuthority) new SimpleGrantedAuthority(p))
                        .toList()
        );
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }

    private static String getJwsFromRequest(final HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || authHeader.length() < 83 || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.substring(7);
    }

    private static boolean isJwsExpired(Date expiration) {
        return (expiration == null) || (new Date().compareTo(expiration) >= 0);
    }
}
