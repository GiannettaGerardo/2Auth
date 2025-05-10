package twoauth.backend.security.service.registration;

import org.springframework.lang.Nullable;

public interface ConfirmRegistration
{
    @Nullable
    String getUniqueSecureToken();
    boolean sendConfirmationRequest();
}
