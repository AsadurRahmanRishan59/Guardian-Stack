package com.rishan.guardianstack.masteradmin.audit.user;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class UserRoleAuditHelper {

    private final EntityManager entityManager;

    /**
     * Fetches the roles assigned to a user at a specific Envers revision.
     * This queries the audited join table (gs_user_roles_aud) via native SQL
     * because Envers does not natively traverse collection joins across revisions.
     * Strategy: find the most recent role snapshot at or before the given revisionNumber.
     */
    @SuppressWarnings("unchecked")
    public Set<String> getRolesAtRevision(Long userId, Long revisionNumber) {
        try {
            // We join the audit bridge table with the actual roles table
            List<String> roles = entityManager.createNativeQuery("""
            SELECT r.role_name
            FROM public.gs_roles r
            JOIN public.gs_user_roles_aud ura ON r.role_id = ura.role_id
            WHERE ura.user_id = :userId
              AND ura.rev = (
                  /* FIND THE MOST RECENT STATE OF ROLES FOR THIS USER\s
                     THAT IS LESS THAN OR EQUAL TO THE INVESTIGATED REVISION */
                  SELECT MAX(inner_ura.rev)
                  FROM public.gs_user_roles_aud inner_ura
                  WHERE inner_ura.user_id = :userId
                    AND inner_ura.rev <= :rev
              )
              AND ura.revtype != 2 -- Exclude rows where the role was DELETED at this rev
           \s""")
                    .setParameter("userId", userId)
                    .setParameter("rev", revisionNumber)
                    .getResultList();

            return roles == null ? Collections.emptySet() : Set.copyOf(roles);
        } catch (Exception e) {
            // Log the error for the Master Admin logs
            return Collections.emptySet();
        }
    }
}