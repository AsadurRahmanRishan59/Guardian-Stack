package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import com.rishan.guardianstack.masteradmin.audit.tariff.motor.filter.MotorTariffAuditFilterRequest;
import com.rishan.guardianstack.tariff.motor.MotorTariff;
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
public class MotorTariffAuditRepository {

    private final EntityManager entityManager;

    @SuppressWarnings("unchecked")
    public List<Object[]> findAuditRevisions(MotorTariffAuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(MotorTariff.class, false, true);
        buildCriteria(filter).forEach(query::add);
        query.addOrder(AuditEntity.revisionNumber().desc());
        query.setFirstResult(filter.page() * filter.size());
        query.setMaxResults(filter.size());
        return query.getResultList();
    }

    public Long countAuditRevisions(MotorTariffAuditFilterRequest filter) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        AuditQuery query = reader.createQuery()
                .forRevisionsOfEntity(MotorTariff.class, false, true)
                .addProjection(AuditEntity.revisionNumber().count());
        buildCriteria(filter).forEach(query::add);
        return (Long) query.getSingleResult();
    }

    /**
     * Returns the target revision and its immediate predecessor for diff computation.
     * Index 0 = target, index 1 = predecessor (may be absent for first revision).
     */
    @SuppressWarnings("unchecked")
    public List<Object[]> findRevisionAndPredecessor(Integer tariffKey, Long revisionNumber) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        List<Object[]> result = new ArrayList<>();

        List<Object[]> target = reader.createQuery()
                .forRevisionsOfEntity(MotorTariff.class, false, true)
                .add(AuditEntity.id().eq(tariffKey))
                .add(AuditEntity.revisionNumber().eq(revisionNumber))
                .getResultList();
        if (target.isEmpty()) return result;
        result.add(target.getFirst());

        List<Object[]> predecessor = reader.createQuery()
                .forRevisionsOfEntity(MotorTariff.class, false, true)
                .add(AuditEntity.id().eq(tariffKey))
                .add(AuditEntity.revisionNumber().lt(revisionNumber))
                .addOrder(AuditEntity.revisionNumber().desc())
                .setMaxResults(1)
                .getResultList();
        if (!predecessor.isEmpty()) result.add(predecessor.getFirst());

        return result;
    }

    /**
     * All revisions for a single tariff, newest-first (for the drill-down panel).
     */
    @SuppressWarnings("unchecked")
    public List<Object[]> findAllRevisionsByTariffKey(Integer tariffKey) {
        AuditReader reader = AuditReaderFactory.get(entityManager);
        return reader.createQuery()
                .forRevisionsOfEntity(MotorTariff.class, false, true)
                .add(AuditEntity.id().eq(tariffKey))
                .addOrder(AuditEntity.revisionNumber().desc())
                .getResultList();
    }

    // ─────────────────────────────────────────────────────────────────────────

    private List<AuditCriterion> buildCriteria(MotorTariffAuditFilterRequest filter) {
        List<AuditCriterion> c = new ArrayList<>();

        if (filter.tariffKey() != null)
            c.add(AuditEntity.id().eq(filter.tariffKey()));

        if (filter.tariffType() != null && !filter.tariffType().isBlank())
            c.add(AuditEntity.property("tariffType").ilike("%" + filter.tariffType().trim() + "%"));

        if (filter.changedBy() != null && !filter.changedBy().isBlank())
            c.add(AuditEntity.revisionProperty("username").ilike("%" + filter.changedBy().trim() + "%"));

        if (filter.ipAddress() != null && !filter.ipAddress().isBlank())
            c.add(AuditEntity.revisionProperty("ipAddress").ilike(filter.ipAddress().trim() + "%"));

        if (filter.revisionTypes() != null && !filter.revisionTypes().isEmpty()) {
            List<org.hibernate.envers.RevisionType> types = filter.revisionTypes().stream()
                    .map(s -> switch (s.toUpperCase()) {
                        case "ADD", "CREATED"  -> org.hibernate.envers.RevisionType.ADD;
                        case "DEL", "DELETED"  -> org.hibernate.envers.RevisionType.DEL;
                        default                -> org.hibernate.envers.RevisionType.MOD;
                    })
                    .toList();
            c.add(foldOr(types));
        }

        if (filter.from() != null)
            c.add(AuditEntity.revisionProperty("timestamp").ge(
                    filter.from().toInstant(ZoneOffset.UTC).toEpochMilli()));
        if (filter.to() != null)
            c.add(AuditEntity.revisionProperty("timestamp").le(
                    filter.to().toInstant(ZoneOffset.UTC).toEpochMilli()));

        return c;
    }

    private AuditCriterion foldOr(List<org.hibernate.envers.RevisionType> types) {
        AuditCriterion acc = AuditEntity.revisionType().eq(types.get(0));
        for (int i = 1; i < types.size(); i++) {
            acc = AuditEntity.or(acc, AuditEntity.revisionType().eq(types.get(i)));
        }
        return acc;
    }
}