package twoauth.backend.security.service.registration;

public interface ConfirmRegistrationFactory {
    ConfirmRegistration newConfirmRegistration(String userEmail);
}
