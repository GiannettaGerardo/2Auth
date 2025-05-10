package twoauth.backend.security.repository;

import twoauth.backend.security.model.User;

import java.util.Optional;

public interface UserRepository
{
    String TABLE = "users";

    Optional<User.SecureDto> findById(String email);
    boolean optimisticLockUpdate(User.SecureDto user);
    boolean delete(String email);
}
