package com.rishan.guardianstack.auth.model;

import com.rishan.guardianstack.core.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "gs_users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userId;

    @Column(nullable = false)
    private String username;

    @Column(unique = true, length = 50)
    private String email;

    @Column(nullable = false, length = 120)
    private String password;

    @Builder.Default
    private boolean accountNonLocked = true;
    @Builder.Default
    private boolean accountNonExpired = true;
    @Builder.Default
    private boolean credentialsNonExpired = true;
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "credentials_expiry_date")
    private LocalDate credentialsExpiryDate;

    @Column(name = "account_expiry_date")
    private LocalDate accountExpiryDate;

    @Column(name = "sign_up_method")
    @Enumerated(EnumType.STRING)
    private SignUpMethod signUpMethod;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "gs_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();
}