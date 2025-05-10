package twoauth.backend.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import twoauth.backend.security.repository.UserSecurityRepository;


@Service
@RequiredArgsConstructor
class CustomUserDetailsService implements UserDetailsService
{
    private final UserSecurityRepository userRepository;

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
