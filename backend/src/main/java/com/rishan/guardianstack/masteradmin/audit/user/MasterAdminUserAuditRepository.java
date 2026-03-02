package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.hibernate.envers.AuditReader;
import org.hibernate.envers.AuditReaderFactory;
import org.hibernate.envers.query.AuditEntity;
import org.hibernate.envers.query.AuditQuery;
import org.hibernate.envers.query.criteria.AuditCriterion;
import org.springframework.stereotype.Repository;

import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class MasterAdminUserAuditRepository {

    private final EntityManager entityManager;

    /**
     * Returns a filtered, paginated list of (GsUser revision, RevisionInfo, RevisionType)
     * triples from Hibernate Envers.
     * Each element in the list is Object[3]:
     *   [0] = GsUser (snapshot at that revision)
     *   [1] = CustomRevisionEntity (contains username, ip_address, revtstmp)
     *   [2] = RevisionType (ADD, MOD, DEL)
     */
    @SuppressWarnings("unchecked")
    public List<Object[]> findAuditRevisions(AuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);

        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true); // false=include revision info, true=include deleted

        List<AuditCriterion> criteria = buildCriteria(filter);
        criteria.forEach(query::add);

        // Sort by revision number DESC (newest first — required for UI diff logic)
        query.addOrder(AuditEntity.revisionNumber().desc());

        // Pagination
        query.setFirstResult(filter.page() * filter.size());
        query.setMaxResults(filter.size());

        return query.getResultList();
    }

    /**
     * Count total results for pagination metadata.
     */
    public Long countAuditRevisions(AuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);

        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .addProjection(AuditEntity.revisionNumber().count());

        List<AuditCriterion> criteria = buildCriteria(filter);
        criteria.forEach(query::add);

        return (Long) query.getSingleResult();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    private List<AuditCriterion> buildCriteria(AuditFilterRequest filter) {
        List<AuditCriterion> criteria = new ArrayList<>();

        // Filter by userId
        if (filter.userId() != null) {
            criteria.add(AuditEntity.property("id").eq(filter.userId()));
        }

        // Filter by email (exact match — for partial, use native SQL approach below)
        if (filter.email() != null && !filter.email().isBlank()) {
            criteria.add(AuditEntity.property("email").ilike("%" + filter.email().trim() + "%"));
        }

        // Filter by changedBy (stored in revinfo.username)
        if (filter.changedBy() != null && !filter.changedBy().isBlank()) {
            criteria.add(
                    AuditEntity.revisionProperty("username").ilike("%" + filter.changedBy().trim() + "%")
            );
        }

        // Filter by IP address prefix
        if (filter.ipAddress() != null && !filter.ipAddress().isBlank()) {
            criteria.add(
                    AuditEntity.revisionProperty("ipAddress").ilike(filter.ipAddress().trim() + "%")
            );
        }

        // Filter by revision type (ADD=0, MOD=1, DEL=2)
        // Corrected logic for Revision Type 'OR' criteria
        if (filter.revisionTypes() != null && !filter.revisionTypes().isEmpty()) {
            List<org.hibernate.envers.RevisionType> types = filter.revisionTypes().stream()
                    .map(this::mapRevisionType)
                    .toList();

            if (types.size() == 1) {
                criteria.add(AuditEntity.revisionType().eq(types.getFirst()));
            } else if (types.size() > 1) {
                // Build the OR chain properly
                AuditCriterion orChain = AuditEntity.revisionType().eq(types.getFirst());
                for (int i = 1; i < types.size(); i++) {
                    orChain = AuditEntity.or(orChain, AuditEntity.revisionType().eq(types.get(i)));
                }
                criteria.add(orChain);
            }
        }

        // Date range filter using revtstmp (milliseconds epoch)
        if (filter.from() != null) {
            long fromMs = filter.from().toInstant(ZoneOffset.UTC).toEpochMilli();
            criteria.add(AuditEntity.revisionProperty("timestamp").ge(fromMs));
        }
        if (filter.to() != null) {
            long toMs = filter.to().toInstant(ZoneOffset.UTC).toEpochMilli();
            criteria.add(AuditEntity.revisionProperty("timestamp").le(toMs));
        }

        return criteria;
    }

    private org.hibernate.envers.RevisionType mapRevisionType(String type) {
        return switch (type.toUpperCase()) {
            case "ADD", "CREATED" -> org.hibernate.envers.RevisionType.ADD;
            case "DEL", "DELETED" -> org.hibernate.envers.RevisionType.DEL;
            default -> org.hibernate.envers.RevisionType.MOD;
        };
    }
}