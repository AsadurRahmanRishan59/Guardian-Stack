package com.rishan.guardianstack.masteradmin.audit.user;

import org.springframework.stereotype.Component;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Component
public class AuditDiffMapper {

    private static final DateTimeFormatter DT_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public AuditDiffDTO compute(MasterAdminUserAuditSnapshot current,
                                MasterAdminUserAuditSnapshot previous) {
        if (previous == null) {
            return AuditDiffDTO.builder()
                    .previousRevisionNumber(null).previousChangedBy(null)
                    .changedFields(Collections.emptyList())
                    .unchangedFields(Collections.emptyList())
                    .addedRoles(current.roles() != null ? current.roles() : Set.of())
                    .removedRoles(Set.of())
                    .criticalChange(false)
                    .adminEscalation(hasAdminRole(current.roles()))
                    .build();
        }

        List<AuditDiffDTO.DiffField> changed   = new ArrayList<>();
        List<AuditDiffDTO.DiffField> unchanged = new ArrayList<>();

        diffBoolean("accountLocked",      "Account Locked",       true,  current.accountLocked(),      previous.accountLocked(),      changed, unchanged);
        diffBoolean("enabled",            "Account Enabled",      true,  current.enabled(),             previous.enabled(),             changed, unchanged);
        diffBoolean("mustChangePassword", "Must Change Password", false, current.mustChangePassword(),  previous.mustChangePassword(),  changed, unchanged);
        diffString("email",           "Email",         current.email(),        previous.email(),        changed, unchanged);
        diffString("username",        "Username",      current.username(),     previous.username(),     changed, unchanged);
        diffString("signUpMethod",    "Sign-up Method",
                current.signUpMethod()  != null ? current.signUpMethod().name()  : null,
                previous.signUpMethod() != null ? previous.signUpMethod().name() : null,
                changed, unchanged);
        diffDateTime("accountExpiryDate",     "Account Expiry",       current.accountExpiryDate(),     previous.accountExpiryDate(),     changed, unchanged);
        diffDateTime("credentialsExpiryDate", "Credentials Expiry",   current.credentialsExpiryDate(), previous.credentialsExpiryDate(), changed, unchanged);
        diffDateTime("lastPasswordChange",    "Last Password Change", current.lastPasswordChange(),    previous.lastPasswordChange(),    changed, unchanged);

        Set<String> currRoles = current.roles()  != null ? current.roles()  : Set.of();
        Set<String> prevRoles = previous.roles() != null ? previous.roles() : Set.of();
        Set<String> added   = new HashSet<>(currRoles); added.removeAll(prevRoles);
        Set<String> removed = new HashSet<>(prevRoles); removed.removeAll(currRoles);

        if (!added.isEmpty() || !removed.isEmpty()) {
            changed.add(AuditDiffDTO.DiffField.builder()
                    .fieldName("roles").fieldLabel("Roles").fieldType("ROLES")
                    .previousValue(String.join(", ", prevRoles))
                    .currentValue(String.join(", ", currRoles))
                    .critical(added.contains("ROLE_ADMIN") || removed.contains("ROLE_ADMIN"))
                    .build());
        } else {
            unchanged.add(AuditDiffDTO.DiffField.builder()
                    .fieldName("roles").fieldLabel("Roles").fieldType("ROLES")
                    .previousValue(String.join(", ", prevRoles))
                    .currentValue(String.join(", ", currRoles))
                    .critical(false).build());
        }

        boolean criticalChange  = changed.stream().anyMatch(AuditDiffDTO.DiffField::critical);
        boolean adminEscalation = added.contains("ROLE_ADMIN");

        return AuditDiffDTO.builder()
                .previousRevisionNumber(previous.revisionNumber())
                .previousChangedBy(previous.changedBy())
                .changedFields(changed).unchangedFields(unchanged)
                .addedRoles(added).removedRoles(removed)
                .criticalChange(criticalChange).adminEscalation(adminEscalation)
                .build();
    }

    private void diffBoolean(String name, String label, boolean isCritical,
                             Boolean curr, Boolean prev,
                             List<AuditDiffDTO.DiffField> changed,
                             List<AuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr.toString() : "null";
        String p = prev != null ? prev.toString() : "null";
        var f = AuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("BOOLEAN")
                .previousValue(p).currentValue(c)
                .critical(isCritical && !c.equals(p)).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private void diffString(String name, String label, String curr, String prev,
                            List<AuditDiffDTO.DiffField> changed,
                            List<AuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr : "";
        String p = prev != null ? prev : "";
        var f = AuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("STRING")
                .previousValue(p).currentValue(c).critical(false).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private void diffDateTime(String name, String label,
                              java.time.LocalDateTime curr, java.time.LocalDateTime prev,
                              List<AuditDiffDTO.DiffField> changed,
                              List<AuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr.format(DT_FMT) : "—";
        String p = prev != null ? prev.format(DT_FMT) : "—";
        var f = AuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("DATETIME")
                .previousValue(p).currentValue(c).critical(false).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private boolean hasAdminRole(Set<String> roles) {
        return roles != null && roles.contains("ROLE_ADMIN");
    }
}