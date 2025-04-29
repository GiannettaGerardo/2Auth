package twoauth.backend.security.repository;

import twoauth.backend.security.model.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UserRepository
{
    String TABLE = "users";

    Optional<UserDetails> findUserDetailsById(String email);
    Optional<User.NoPasswordDto> findById(String email);
    boolean save(User user);
    boolean optimisticLockUpdate(User.NoPasswordDto user);
    boolean delete(String email);
}
