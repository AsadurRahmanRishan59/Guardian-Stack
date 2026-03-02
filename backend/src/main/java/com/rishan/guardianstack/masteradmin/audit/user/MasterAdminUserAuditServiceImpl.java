package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.core.domain.CustomRevisionEntity;
import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
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
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MasterAdminUserAuditServiceImpl implements MasterAdminUserAuditService {

    private final MasterAdminUserAuditRepository auditRepository;
    private final UserRoleAuditHelper roleAuditHelper;  // see section 6

    @Override
    public Page<MasterAdminUserAuditDTO> getUserAuditHistory(AuditFilterRequest filter) {
        List<Object[]> rawRevisions = auditRepository.findAuditRevisions(filter);
        Long totalCount = auditRepository.countAuditRevisions(filter);

        List<MasterAdminUserAuditDTO> dtos = rawRevisions.stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());

        return new PageImpl<>(dtos, PageRequest.of(filter.page(), filter.size()), totalCount);
    }

    @Override
    public List<MasterAdminUserAuditDTO> getUserAuditHistoryByUserId(Long userId) {
        AuditFilterRequest filter = new AuditFilterRequest(
                userId, null, null, null, null, null, null, 0, 500
        );
        return auditRepository.findAuditRevisions(filter).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core mapping: Object[3] → MasterAdminUserAuditDTO
    // ─────────────────────────────────────────────────────────────────────────

    private MasterAdminUserAuditDTO mapToDTO(Object[] revisionTriple) {
        User userSnapshot      = (User)               revisionTriple[0];
        CustomRevisionEntity rev = (CustomRevisionEntity) revisionTriple[1];
        RevisionType revType     = (RevisionType)         revisionTriple[2];

        // Fetch roles at this revision from the join table audit
        Set<String> roles = roleAuditHelper.getRolesAtRevision(
                userSnapshot.getUserId(), rev.getRev()
        );

        return MasterAdminUserAuditDTO.builder()
                .revisionNumber(rev.getRev())
                .revisionType(mapRevisionType(revType))
                .timestamp(toLocalDateTime(rev.getTimestamp()))
                .changedBy(rev.getUsername())
                .ipAddress(rev.getIpAddress())
                // User snapshot
                .userId(userSnapshot.getUserId())
                .username(userSnapshot.getUsername())
                .email(userSnapshot.getEmail())
                .signUpMethod(userSnapshot.getSignUpMethod())
                .roles(roles)
                .enabled(userSnapshot.isEnabled())
                .accountLocked(userSnapshot.isAccountLocked())
                .accountExpiryDate(userSnapshot.getAccountExpiryDate())
                .credentialsExpiryDate(userSnapshot.getCredentialsExpiryDate())
                .lastPasswordChange(userSnapshot.getLastPasswordChange())
                .build();
    }

    private String mapRevisionType(RevisionType type) {
        return switch (type) {
            case ADD -> "CREATED";
            case MOD -> "MODIFIED";
            case DEL -> "DELETED";
        };
    }

    private LocalDateTime toLocalDateTime(long epochMillis) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneOffset.UTC);
    }
}