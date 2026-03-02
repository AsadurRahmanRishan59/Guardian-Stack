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

    @SuppressWarnings("unchecked")
    public List<Object[]> findAuditRevisions(AuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true);
        buildCriteria(filter).forEach(query::add);
        query.addOrder(AuditEntity.revisionNumber().desc());
        query.setFirstResult(filter.page() * filter.size());
        query.setMaxResults(filter.size());
        return query.getResultList();
    }

    public Long countAuditRevisions(AuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .addProjection(AuditEntity.revisionNumber().count());
        buildCriteria(filter).forEach(query::add);
        return (Long) query.getSingleResult();
    }

    @SuppressWarnings("unchecked")
    public List<Object[]> findRevisionAndPredecessor(Long userId, Long revisionNumber) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        List<Object[]> result = new ArrayList<>();

        List<Object[]> target = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.property("id").eq(userId))
                .add(AuditEntity.revisionNumber().eq(revisionNumber))
                .getResultList();
        if (target.isEmpty()) return result;
        result.add(target.getFirst());

        List<Object[]> predecessor = reader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.property("id").eq(userId))
                .add(AuditEntity.revisionNumber().lt(revisionNumber))
                .addOrder(AuditEntity.revisionNumber().desc())
                .setMaxResults(1)
                .getResultList();
        if (!predecessor.isEmpty()) result.add(predecessor.getFirst());

        return result;
    }

    private List<AuditCriterion> buildCriteria(AuditFilterRequest filter) {
        List<AuditCriterion> c = new ArrayList<>();
        if (filter.userId() != null)
            c.add(AuditEntity.property("id").eq(filter.userId()));
        if (filter.email() != null && !filter.email().isBlank())
            c.add(AuditEntity.property("email").ilike("%" + filter.email().trim() + "%"));
        if (filter.changedBy() != null && !filter.changedBy().isBlank())
            c.add(AuditEntity.revisionProperty("username").ilike("%" + filter.changedBy().trim() + "%"));
        if (filter.ipAddress() != null && !filter.ipAddress().isBlank())
            c.add(AuditEntity.revisionProperty("ipAddress").ilike(filter.ipAddress().trim() + "%"));

        // AFTER (fixed) — replace the whole block with:
        if (filter.revisionTypes() != null && !filter.revisionTypes().isEmpty()) {
            List<org.hibernate.envers.RevisionType> types = filter.revisionTypes().stream()
                    .map(s -> switch (s.toUpperCase()) {
                        case "ADD", "CREATED" -> org.hibernate.envers.RevisionType.ADD;
                        case "DEL", "DELETED" -> org.hibernate.envers.RevisionType.DEL;
                        default               -> org.hibernate.envers.RevisionType.MOD;
                    })
                    .toList();

            c.add(foldOr(types));
        }

        if (filter.from() != null)
            c.add(AuditEntity.revisionProperty("timestamp").ge(filter.from().toInstant(ZoneOffset.UTC).toEpochMilli()));
        if (filter.to() != null)
            c.add(AuditEntity.revisionProperty("timestamp").le(filter.to().toInstant(ZoneOffset.UTC).toEpochMilli()));
        return c;
    }

    /**
     * Folds a list of RevisionTypes into a left-associative chain of binary
     * AuditEntity.or(lhs, rhs) calls.
     *
     * AuditEntity.or() signature:  or(AuditCriterion lhs, AuditCriterion rhs)
     * It does NOT accept an array — that's what caused the compile error.
     *
     * For [ADD, MOD, DEL] this produces:
     *   or( or(type==ADD, type==MOD), type==DEL )
     *
     * Single-element list short-circuits to eq() with no or() wrapper.
     */
    private AuditCriterion foldOr(List<org.hibernate.envers.RevisionType> types) {
        AuditCriterion acc = AuditEntity.revisionType().eq(types.get(0));
        for (int i = 1; i < types.size(); i++) {
            acc = AuditEntity.or(acc, AuditEntity.revisionType().eq(types.get(i)));
        }
        return acc;
    }
}