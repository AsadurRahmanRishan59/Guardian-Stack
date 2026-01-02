package com.rishan.guardianstack.masteradmin.user;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserSearchCriteria;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class MasterAdminUserSpecification {

    public static Specification<User> withFilters(MasterAdminUserSearchCriteria criteria) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 1. Partial Match for Username (LIKE %name%)
            if (StringUtils.hasText(criteria.username())) {
                predicates.add(cb.like(cb.lower(root.get("username")),
                        "%" + criteria.username().toLowerCase() + "%"));
            }

            // 2. Exact Match for Email
            if (StringUtils.hasText(criteria.email())) {
                predicates.add(cb.equal(cb.lower(root.get("email")),
                        criteria.email().toLowerCase()));
            }

            // 3. Boolean Flags (Lock, Enabled, Expiry)
            // Note: In Search, we might want to make these Boolean objects
            // to allow "Don't Filter" vs "True" vs "False"
            predicates.add(cb.equal(root.get("accountNonLocked"), criteria.accountNonLocked()));
            predicates.add(cb.equal(root.get("accountNonExpired"), criteria.accountNonExpired()));
            predicates.add(cb.equal(root.get("enabled"), criteria.enabled()));

            // 4. Role-based Filtering (Join logic)
            if (!CollectionUtils.isEmpty(criteria.roleIds())) {
                Join<User, Role> roleJoin = root.join("roles");
                predicates.add(roleJoin.get("roleId").in(criteria.roleIds()));
                // Ensure distinct results if a user has multiple roles being filtered
                query.distinct(true);
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}