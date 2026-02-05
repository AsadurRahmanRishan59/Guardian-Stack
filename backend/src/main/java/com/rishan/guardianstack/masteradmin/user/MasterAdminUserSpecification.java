package com.rishan.guardianstack.masteradmin.user;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserSearchCriteria;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class MasterAdminUserSpecification {

    public static Specification<User> withFilters(MasterAdminUserSearchCriteria criteria) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 1. Partial Match for Username
            if (StringUtils.hasText(criteria.username())) {
                predicates.add(cb.like(cb.lower(root.get("username")),
                        "%" + criteria.username().toLowerCase() + "%"));
            }

            // 2. Exact Match for Email
            if (StringUtils.hasText(criteria.email())) {
                predicates.add(cb.equal(cb.lower(root.get("email")),
                        criteria.email().toLowerCase()));
            }

            // --- ADDED: SignUpMethod Filtering ---
            if (criteria.signUpMethod() != null) {
                predicates.add(cb.equal(root.get("signUpMethod"), criteria.signUpMethod()));
            }
            // -------------------------------------

            // 3. Boolean Flags - NULL-SAFE MAPPING
            if (criteria.enabled() != null) {
                predicates.add(cb.equal(root.get("enabled"), criteria.enabled()));
            }

            if (criteria.accountLocked() != null) {
                predicates.add(cb.equal(root.get("accountLocked"), criteria.accountLocked()));
            }

            // Handle Account Expiration
            if (criteria.accountExpired() != null) {
                if (criteria.accountExpired()) { // User wants EXPIRED accounts
                    predicates.add(cb.and(
                            cb.isNotNull(root.get("accountExpiryDate")),
                            cb.lessThanOrEqualTo(root.get("accountExpiryDate"), LocalDateTime.now())
                    ));
                } else { // User wants NON-EXPIRED accounts
                    predicates.add(cb.or(
                            cb.isNull(root.get("accountExpiryDate")),
                            cb.greaterThan(root.get("accountExpiryDate"), LocalDateTime.now())
                    ));
                }
            }

            // Handle Credential Expiration
            if (criteria.credentialExpired() != null) {
                if (criteria.credentialExpired()) {
                    predicates.add(cb.and(
                            cb.isNotNull(root.get("credentialsExpiryDate")),
                            cb.lessThanOrEqualTo(root.get("credentialsExpiryDate"), LocalDateTime.now())
                    ));
                } else {
                    predicates.add(cb.or(
                            cb.isNull(root.get("credentialsExpiryDate")),
                            cb.greaterThan(root.get("credentialsExpiryDate"), LocalDateTime.now())
                    ));
                }
            }

            // 4. Role-based Filtering
            if (!CollectionUtils.isEmpty(criteria.roleIds())) {
                Join<User, Role> roleJoin = root.join("roles");
                predicates.add(roleJoin.get("roleId").in(criteria.roleIds()));
                query.distinct(true);
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}