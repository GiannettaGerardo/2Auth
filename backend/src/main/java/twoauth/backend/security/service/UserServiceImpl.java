package twoauth.backend.security.service;

import twoauth.backend.security.UserNotDeletedException;
import twoauth.backend.security.UserNotFoundException;
import twoauth.backend.security.UserNotSavedException;
import twoauth.backend.security.UserNotUpdatedException;
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
    public User.NoPasswordDto safeGetById(final String email) throws UserNotFoundException
    {
        var user = userRepository.findById(email)
                .orElseThrow(() -> new UserNotFoundException(email));

        return new User.NoPasswordDto(
                user.email(),
                user.firstName(),
                user.lastName(),
                user.creation(),
                user.lastUpdate(),
                user.permissions()
        );
    }

    @Override
    public void save(final User user) throws UserNotSavedException
    {
        if (! userRepository.save(user))
            throw new UserNotSavedException(user.getEmail());
    }

    @Override
    public void update(final User.NoPasswordDto user) throws UserNotUpdatedException
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
