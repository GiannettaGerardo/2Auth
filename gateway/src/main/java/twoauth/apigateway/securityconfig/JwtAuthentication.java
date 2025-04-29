package twoauth.apigateway.securityconfig;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Base64;
import java.util.Collection;
import java.util.Collections;

public class JwtAuthentication implements Authentication
{
    private boolean isAuthenticated;
    private final String jwt;
    private final String subject;

    public JwtAuthentication(final String jwt, final ObjectMapper objectMapper) {
        Assert.isTrue(jwt != null && !jwt.isBlank(), () -> "JWT cannot be null or blank.");
        final String base64Payload = getJwtBase64PayloadSubstring(jwt);
        final String decodedPayload = new String(Base64.getUrlDecoder().decode(base64Payload));
        subject = extractSubjectFromPayload(decodedPayload, objectMapper);
        Assert.isTrue(subject != null && !subject.isBlank(), () -> "JWT Subject cannot be null or blank.");
        this.jwt = jwt;
        isAuthenticated = true;
    }

    private static String getJwtBase64PayloadSubstring(final String jwt) {
        int first = -1, last = -1, len = jwt.length();
        for (int i = 0; i < len; ++i) {
            if (jwt.charAt(i) == '.') {
                if (first == -1)
                    first = i;
                else {
                    last = i;
                    break;
                }
            }
        }
        if (first == -1 || last == -1)
            throw new IllegalArgumentException("Cannot find two points . in JWT string.");

        return jwt.substring(first+1, last);
    }

    private static String extractSubjectFromPayload(final String payload, final ObjectMapper objectMapper) {
        try {
            JsonNode node = objectMapper.readTree(payload);
            node = node.get("sub");
            if (node == null || !node.isTextual())
                throw new IllegalArgumentException("JWT subject incorrect or not found.");
            return node.textValue();
        }
        catch (JsonProcessingException | IllegalArgumentException e) {
            System.err.println("Something went wrong in parsing JWT.");
            throw new IllegalStateException(e);
        }
    }

    public String getToken() {
        return jwt;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return subject;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return Strings.EMPTY;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof JwtAuthentication that)) return false;
        return jwt.equals(that.jwt);
    }

    @Override
    public int hashCode() {
        return jwt.hashCode();
    }
}
