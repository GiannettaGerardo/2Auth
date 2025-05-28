package twoauth.backend.security.configuration;

import twoauth.backend.security.model.StdJwtClaims;
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

        String subject;
        if ((subject = safeGetSubject(payload)) == null) {
            // don't trust the JWT!
            filterChain.doFilter(request, response);
            return;
        }

        List<GrantedAuthority> permissions;
        if ((permissions = safeGetPermissions(payload)) == null) {
            // don't trust the JWT!
            filterChain.doFilter(request, response);
            return;
        }

        final var authToken = new UsernamePasswordAuthenticationToken(subject, null, permissions);
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

    private static String safeGetSubject(final Claims payload) {
        final String subject = payload.getSubject();
        if (subject == null || subject.isBlank()) {
            return null;
        }
        return subject;
    }

    private static List<GrantedAuthority> safeGetPermissions(final Claims payload) {
        if (payload.get(StdJwtClaims.PERMISSIONS) instanceof ArrayList<?> arrayPermissions) {
            final List<GrantedAuthority> grantedAuthorities = new ArrayList<>(arrayPermissions.size());
            for (Object permission : arrayPermissions) {
                if (permission instanceof String strPermission) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(strPermission));
                }
                else return null;
            }
            return grantedAuthorities;
        }
        else return null;
    }
}
