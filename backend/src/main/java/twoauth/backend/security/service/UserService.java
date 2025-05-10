package twoauth.backend.security.service;

import twoauth.backend.exception.UserNotDeletedException;
import twoauth.backend.exception.UserNotFoundException;
import twoauth.backend.exception.UserNotUpdatedException;
import twoauth.backend.security.model.User;

public interface UserService
{
    User.SecureDto safeGetById(String email) throws UserNotFoundException;
    void update(User.SecureDto user) throws UserNotUpdatedException;
    void delete(String email) throws UserNotDeletedException;
}
