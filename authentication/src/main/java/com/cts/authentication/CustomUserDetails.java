package com.cts.authentication; // Make sure this package name matches yours

import com.cts.authentication.entity.User; // Make sure this import matches your User entity's package
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private String userName;
    private String password;
    private List<GrantedAuthority> authorities;
    private User user; // Added this field to hold the full User object

    public CustomUserDetails(User user) {
        this.userName = user.getEmail(); // Assuming email is used as username for login
        this.password = user.getPassword();
        this.authorities = Arrays.stream(user.getRole().split(",")) // Assuming roles are comma-separated
                                 .map(SimpleGrantedAuthority::new)
                                 .collect(Collectors.toList());
        this.user = user; // Initialize the user object
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // New method added to provide access to the underlying User object
    public User getUser() {
        return user;
    }
}