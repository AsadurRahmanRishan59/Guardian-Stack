package com.rishan.guardianstack.auth.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Table(name = "gs_roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    @EqualsAndHashCode.Include
    private Integer roleId;

    @ToString.Exclude
    @Enumerated(EnumType.STRING)
    @Column(name = "role_name", nullable = false, unique = true, length = 50)
    private AppRole roleName;

    @Column(name = "description", length = 255)
    private String description;
}
