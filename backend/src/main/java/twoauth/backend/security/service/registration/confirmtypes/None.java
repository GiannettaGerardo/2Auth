package twoauth.backend.security.service.registration.confirmtypes;

import twoauth.backend.security.service.registration.ConfirmRegistration;

public final class None implements ConfirmRegistration
{
    @Override
    public String getUniqueSecureToken() {
        return null;
    }

    @Override
    public boolean sendConfirmationRequest() {
        return true;
    }

    @Override
    public String toString() {
        return "None{}";
    }
}
