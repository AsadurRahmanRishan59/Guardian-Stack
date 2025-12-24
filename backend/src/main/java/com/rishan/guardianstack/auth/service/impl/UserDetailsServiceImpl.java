package com.rishan.guardianstack.auth.service.impl;

import com.rishan.digitalinsurance.modules.auth.model.User;
import com.rishan.digitalinsurance.modules.auth.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @NonNull
    @Transactional
    public UserDetails loadUserByUsername(@NonNull String identifier) throws UsernameNotFoundException {
        // We search the identifier against both columns
        User user = userRepository.findByEmailOrMobileNumber(identifier, identifier)
                .or(() -> userRepository.findByUsername(identifier)) // Also check username
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with identifier: " + identifier));

        return UserDetailsImpl.build(user);
    }
}