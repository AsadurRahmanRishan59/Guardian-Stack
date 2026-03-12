package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import com.rishan.guardianstack.core.domain.CustomRevisionEntity;
import com.rishan.guardianstack.masteradmin.audit.tariff.motor.filter.MotorTariffAuditFilterRequest;
import com.rishan.guardianstack.tariff.motor.MotorTariff;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.envers.RevisionType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MotorTariffAuditServiceImpl implements MotorTariffAuditService {

    private final MotorTariffAuditRepository auditRepository;
    private final MotorTariffAuditDiffMapper diffMapper;

    // ─── LEFT PANEL ───────────────────────────────────────────────────────────

    @Override
    public Page<MotorTariffAuditTimelineItemDTO> getTimelineItems(MotorTariffAuditFilterRequest filter) {
        List<Object[]> raw   = auditRepository.findAuditRevisions(filter);
        Long           total = auditRepository.countAuditRevisions(filter);

        List<MotorTariffAuditSnapshot> snapshots = raw.stream().map(this::toSnapshot).toList();

        List<MotorTariffAuditTimelineItemDTO> items = new ArrayList<>();
        for (int i = 0; i < snapshots.size(); i++) {
            MotorTariffAuditSnapshot curr = snapshots.get(i);
            MotorTariffAuditSnapshot prev = i + 1 < snapshots.size() ? snapshots.get(i + 1) : null;
            items.add(toTimelineItem(curr, prev));
        }
        return new PageImpl<>(items, PageRequest.of(filter.page(), filter.size()), total);
    }

    // ─── RIGHT PANEL ──────────────────────────────────────────────────────────

    @Override
    public Optional<MotorTariffAuditDTO> getRevisionDetail(Integer tariffKey, Long revisionNumber) {
        List<Object[]> raw = auditRepository.findRevisionAndPredecessor(tariffKey, revisionNumber);
        if (raw.isEmpty()) return Optional.empty();

        MotorTariffAuditSnapshot current  = toSnapshot(raw.get(0));
        MotorTariffAuditSnapshot previous = raw.size() > 1 ? toSnapshot(raw.get(1)) : null;
        MotorTariffAuditDiffDTO  diff     = diffMapper.compute(current, previous);

        return Optional.of(MotorTariffAuditDTO.builder()
                .revisionNumber(current.revisionNumber()).revisionType(current.revisionType())
                .timestamp(current.timestamp()).changedBy(current.changedBy()).ipAddress(current.ipAddress())
                .tariffKey(current.tariffKey()).tariffType(current.tariffType())
                .groupOfVehicle(current.groupOfVehicle()).typeOfVehicle(current.typeOfVehicle())
                .category(current.category())
                .ownDpBasic(current.ownDpBasic()).fullInsValue(current.fullInsValue())
                .actLiability(current.actLiability())
                .fire(current.fire()).theft(current.theft())
                .cyclone(current.cyclone()).earthquake(current.earthquake())
                .isActive(current.isActive())
                .diff(diff).build());
    }

    // ─── DRILL-DOWN ───────────────────────────────────────────────────────────

    @Override
    public List<MotorTariffAuditTimelineItemDTO> getTariffTimeline(Integer tariffKey) {
        List<Object[]> raw = auditRepository.findAllRevisionsByTariffKey(tariffKey);
        List<MotorTariffAuditSnapshot> snapshots = raw.stream().map(this::toSnapshot).toList();
        List<MotorTariffAuditTimelineItemDTO> items = new ArrayList<>();
        for (int i = 0; i < snapshots.size(); i++) {
            items.add(toTimelineItem(snapshots.get(i),
                    i + 1 < snapshots.size() ? snapshots.get(i + 1) : null));
        }
        return items;
    }

    // ─── Mapping helpers ──────────────────────────────────────────────────────

    private MotorTariffAuditSnapshot toSnapshot(Object[] triple) {
        MotorTariff          tariff  = (MotorTariff)          triple[0];
        CustomRevisionEntity rev     = (CustomRevisionEntity) triple[1];
        RevisionType         revType = (RevisionType)         triple[2];

        return MotorTariffAuditSnapshot.builder()
                .revisionNumber(rev.getRev()).revisionType(mapRevType(revType))
                .timestamp(toLocalDateTime(rev.getTimestamp()))
                .changedBy(rev.getUsername()).ipAddress(rev.getIpAddress())
                .tariffKey(tariff.getTariffKey()).tariffType(tariff.getTariffType())
                .groupOfVehicle(tariff.getGroupOfVehicle()).typeOfVehicle(tariff.getTypeOfVehicle())
                .category(tariff.getCategory())
                .ownDpBasic(tariff.getOwnDpBasic()).fullInsValue(tariff.getFullInsValue())
                .actLiability(tariff.getActLiability())
                .fire(tariff.getFire()).theft(tariff.getTheft())
                .cyclone(tariff.getCyclone()).earthquake(tariff.getEarthquake())
                .isActive(tariff.getIsActive())
                .build();
    }

    private MotorTariffAuditTimelineItemDTO toTimelineItem(MotorTariffAuditSnapshot curr,
                                                           MotorTariffAuditSnapshot prev) {
        boolean statusChanged = prev != null &&
                !java.util.Objects.equals(curr.isActive(), prev.isActive());

        return MotorTariffAuditTimelineItemDTO.builder()
                .revisionNumber(curr.revisionNumber()).revisionType(curr.revisionType())
                .timestamp(curr.timestamp()).changedBy(curr.changedBy()).ipAddress(curr.ipAddress())
                .tariffKey(curr.tariffKey()).tariffType(curr.tariffType())
                .groupOfVehicle(curr.groupOfVehicle()).typeOfVehicle(curr.typeOfVehicle())
                .category(curr.category())
                .isActive(Boolean.TRUE.equals(curr.isActive()))
                .statusChanged(statusChanged)
                .build();
    }

    private String mapRevType(RevisionType t) {
        return switch (t) { case ADD -> "CREATED"; case MOD -> "MODIFIED"; case DEL -> "DELETED"; };
    }

    private LocalDateTime toLocalDateTime(long ms) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(ms), ZoneOffset.UTC);
    }
}