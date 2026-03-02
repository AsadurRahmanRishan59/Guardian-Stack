package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
import com.rishan.guardianstack.revision.CustomRevisionEntity;
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
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MasterAdminUserAuditServiceImpl implements MasterAdminUserAuditService {

    private final MasterAdminUserAuditRepository auditRepository;
    private final UserRoleAuditHelper            roleAuditHelper;
    private final AuditDiffMapper                diffMapper;

    @Override
    public Page<AuditTimelineItemDTO> getTimelineItems(AuditFilterRequest filter) {
        List<Object[]> raw  = auditRepository.findAuditRevisions(filter);
        Long total          = auditRepository.countAuditRevisions(filter);
        List<MasterAdminUserAuditSnapshot> snapshots = raw.stream().map(this::toSnapshot).collect(Collectors.toList());

        List<AuditTimelineItemDTO> items = new ArrayList<>();
        for (int i = 0; i < snapshots.size(); i++) {
            MasterAdminUserAuditSnapshot curr = snapshots.get(i);
            MasterAdminUserAuditSnapshot prev = i + 1 < snapshots.size() ? snapshots.get(i + 1) : null;
            items.add(toTimelineItem(curr, prev));
        }
        return new PageImpl<>(items, PageRequest.of(filter.page(), filter.size()), total);
    }

    @Override
    public Optional<MasterAdminUserAuditDTO> getRevisionDetail(Long userId, Long revisionNumber) {
        List<Object[]> raw = auditRepository.findRevisionAndPredecessor(userId, revisionNumber);
        if (raw.isEmpty()) return Optional.empty();

        MasterAdminUserAuditSnapshot current  = toSnapshot(raw.get(0));
        MasterAdminUserAuditSnapshot previous = raw.size() > 1 ? toSnapshot(raw.get(1)) : null;
        AuditDiffDTO diff = diffMapper.compute(current, previous);

        return Optional.of(MasterAdminUserAuditDTO.builder()
                .revisionNumber(current.revisionNumber()).revisionType(current.revisionType())
                .timestamp(current.timestamp()).changedBy(current.changedBy()).ipAddress(current.ipAddress())
                .userId(current.userId()).username(current.username()).email(current.email())
                .signUpMethod(current.signUpMethod()).roles(current.roles())
                .enabled(current.enabled()).accountLocked(current.accountLocked())
                .accountExpiryDate(current.accountExpiryDate())
                .credentialsExpiryDate(current.credentialsExpiryDate())
                .lastPasswordChange(current.lastPasswordChange())
                .diff(diff).build());
    }

    @Override
    public List<AuditTimelineItemDTO> getUserTimeline(Long userId) {
        List<Object[]> raw = auditRepository.findAuditRevisions(
                new AuditFilterRequest(userId, null, null, null, null, null, null, 0, 500));
        List<MasterAdminUserAuditSnapshot> snapshots = raw.stream().map(this::toSnapshot).collect(Collectors.toList());
        List<AuditTimelineItemDTO> items = new ArrayList<>();
        for (int i = 0; i < snapshots.size(); i++) {
            items.add(toTimelineItem(snapshots.get(i), i + 1 < snapshots.size() ? snapshots.get(i + 1) : null));
        }
        return items;
    }

    private MasterAdminUserAuditSnapshot toSnapshot(Object[] triple) {
        GsUser               user    = (GsUser)               triple[0];
        CustomRevisionEntity rev     = (CustomRevisionEntity) triple[1];
        RevisionType         revType = (RevisionType)         triple[2];
        Set<String> roles = roleAuditHelper.getRolesAtRevision(user.getUserId(), rev.getId());
        return MasterAdminUserAuditSnapshot.builder()
                .revisionNumber(rev.getId()).revisionType(mapRevType(revType))
                .timestamp(toLocalDateTime(rev.getTimestamp()))
                .changedBy(rev.getUsername()).ipAddress(rev.getIpAddress())
                .userId(user.getUserId()).username(user.getUsername()).email(user.getEmail())
                .signUpMethod(user.getSignUpMethod()).roles(roles)
                .enabled(user.isEnabled()).accountLocked(user.isAccountLocked())
                .mustChangePassword(user.isMustChangePassword())
                .accountExpiryDate(user.getAccountExpiryDate())
                .credentialsExpiryDate(user.getCredentialsExpiryDate())
                .lastPasswordChange(user.getLastPasswordChange())
                .build();
    }

    private AuditTimelineItemDTO toTimelineItem(MasterAdminUserAuditSnapshot curr,
                                                MasterAdminUserAuditSnapshot prev) {
        boolean adminEscalation = false;
        if (prev != null && curr.roles() != null) {
            adminEscalation = curr.roles().contains("ROLE_ADMIN") &&
                    (prev.roles() == null || !prev.roles().contains("ROLE_ADMIN"));
        } else if (prev == null && curr.roles() != null) {
            adminEscalation = curr.roles().contains("ROLE_ADMIN");
        }
        return AuditTimelineItemDTO.builder()
                .revisionNumber(curr.revisionNumber()).revisionType(curr.revisionType())
                .timestamp(curr.timestamp()).changedBy(curr.changedBy()).ipAddress(curr.ipAddress())
                .userId(curr.userId()).email(curr.email())
                .accountLocked(Boolean.TRUE.equals(curr.accountLocked()))
                .enabled(Boolean.TRUE.equals(curr.enabled()))
                .hasAdminRoleEscalation(adminEscalation)
                .build();
    }

    private String mapRevType(RevisionType t) {
        return switch (t) { case ADD -> "CREATED"; case MOD -> "MODIFIED"; case DEL -> "DELETED"; };
    }
    private LocalDateTime toLocalDateTime(long ms) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(ms), ZoneOffset.UTC);
    }
}