package twoauth.backend.security.service.registration;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import twoauth.backend.security.model.User;
import twoauth.backend.security.repository.UserSecurityRepository;
import twoauth.backend.security.service.registration.confirmtypes.None;

import java.util.Date;

@Service
class RegistrationServiceImpl implements RegistrationService
{
    private final PasswordEncoder passwordEncoder;
    private final UserSecurityRepository userRepository;
    private final ConfirmRegistrationFactory confirmRegistrationFactory;

    public RegistrationServiceImpl(
            final PasswordEncoder passwordEncoder,
            final UserSecurityRepository userRepository,
            final ConfirmRegistrationFactory confirmRegistrationFactory
    ) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.confirmRegistrationFactory = confirmRegistrationFactory;
    }

    @Override
    public boolean registration(final User.RegistrationDto userDto)
    {
        final var now = new Date();
        final ConfirmRegistration confirmRegistration =
                confirmRegistrationFactory.newConfirmRegistration(userDto.getEmail());

        final User user = new User(
                userDto.getEmail(),
                passwordEncoder.encode(userDto.getPassword()),
                userDto.getFirstName(),
                userDto.getLastName(),
                now,
                now,
                userDto.getPermissions(),
                confirmRegistration instanceof None,
                confirmRegistration.getUniqueSecureToken()
        );
        userDto.eraseCredentials();

        final boolean isSaved = userRepository.save(user);
        user.eraseCredentials();
        if (isSaved && !confirmRegistration.sendConfirmationRequest()) {
            // TODO handle this specific error
            System.err.println("User saved but Registration Confirmation not sent.");
            return false;
        }
        return isSaved;
    }
}
