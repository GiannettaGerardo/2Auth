package twoauth.backend.security.service.registration;

import twoauth.backend.security.model.User;

public interface RegistrationService {
    boolean registration(User.RegistrationDto userDto);
}
