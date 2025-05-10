package twoauth.backend.security.service.registration.confirmtypes;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import twoauth.backend.security.service.registration.ConfirmRegistration;

abstract class JwtsHS512Token implements ConfirmRegistration
{
    @JsonIgnore
    protected final String uniqueSecureToken;

    protected JwtsHS512Token() {
        uniqueSecureToken = Encoders.BASE64.encode(Jwts.SIG.HS512.key().build().getEncoded());
    }

    @Override
    public String getUniqueSecureToken() {
        return uniqueSecureToken;
    }

    @Override
    public String toString() {
        return "JwtsHS512Token{}";
    }
}
