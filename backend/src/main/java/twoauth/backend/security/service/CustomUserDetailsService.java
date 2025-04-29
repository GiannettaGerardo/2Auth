package twoauth.backend.security.service;

import twoauth.backend.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
class CustomUserDetailsService implements UserDetailsService
{
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException
    {
        System.out.println("UserDetailsService called");

        return userRepository.findUserDetailsById(email)
                .orElseThrow(() -> {
                    System.err.printf("User %s not found.%n", email);
                    return new UsernameNotFoundException("User not found.");
                });
    }
}
