package twoauth.backend.security.service;

import twoauth.backend.exception.UserNotDeletedException;
import twoauth.backend.exception.UserNotFoundException;
import twoauth.backend.exception.UserNotUpdatedException;
import twoauth.backend.security.model.User;
import twoauth.backend.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService
{
    private final UserRepository userRepository;

    @Override
    public User.SecureDto safeGetById(final String email) throws UserNotFoundException
    {
        var user = userRepository.findById(email)
                .orElseThrow(() -> new UserNotFoundException(email));

        return new User.SecureDto(
                user.email(),
                user.firstName(),
                user.lastName(),
                user.creation(),
                user.lastUpdate(),
                user.permissions(),
                user.isActive()
        );
    }

    @Override
    public void update(final User.SecureDto user) throws UserNotUpdatedException
    {
        if (! userRepository.optimisticLockUpdate(user))
            throw new UserNotUpdatedException(user.email());
    }

    @Override
    public void delete(final String email) throws UserNotDeletedException
    {
        if (! userRepository.delete(email))
            throw new UserNotDeletedException(email);
    }
}
