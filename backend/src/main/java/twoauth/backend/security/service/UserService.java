package twoauth.backend.security.service;

import twoauth.backend.security.UserNotDeletedException;
import twoauth.backend.security.UserNotFoundException;
import twoauth.backend.security.UserNotSavedException;
import twoauth.backend.security.UserNotUpdatedException;
import twoauth.backend.security.model.User;

public interface UserService
{
    User.NoPasswordDto safeGetById(String email) throws UserNotFoundException;
    void save(User user) throws UserNotSavedException;
    void update(User.NoPasswordDto user) throws UserNotUpdatedException;
    void delete(String email) throws UserNotDeletedException;
}
