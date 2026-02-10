package com.rishan.guardianstack.core.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.envers.RevisionEntity;
import org.hibernate.envers.RevisionNumber;
import org.hibernate.envers.RevisionTimestamp;

import java.io.Serializable;

/**
 * Custom Envers Revision Entity
 *
 * This replaces the default REVINFO table with our custom version
 * that tracks WHO made the change and FROM WHERE (IP address)
 *
 * Envers will automatically populate:
 * - rev: auto-incremented revision number
 * - revtstmp: timestamp in milliseconds
 *
 * We manually populate in RevisionListener:
 * - username: who made the change
 * - ipAddress: from where the change was made
 */
@Entity
@Table(name = "revinfo")
@RevisionEntity(CustomRevisionListener.class)
@Getter
@Setter
public class CustomRevisionEntity implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @RevisionNumber
    @Column(name = "rev")
    private Long rev;

    @RevisionTimestamp
    @Column(name = "revtstmp")
    private Long timestamp;

    /**
     * Username who made the change
     * Populated from Spring Security context
     */
    @Column(name = "username", length = 255)
    private String username;

    /**
     * IP address from where the change was made
     * Populated from HttpServletRequest
     */
    @Column(name = "ip_address", length = 45)  // IPv6 max length is 45
    private String ipAddress;
}