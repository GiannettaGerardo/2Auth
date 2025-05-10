package twoauth.backend.security.repository;

import org.springframework.security.core.userdetails.UserDetails;
import twoauth.backend.security.model.User;

import java.util.Optional;

public interface UserSecurityRepository
{
    String TABLE = "users";

    Optional<UserDetails> findUserDetailsById(String email);
    boolean save(User user);
    boolean optimisticLockEnableUserAccount(User user);
}
