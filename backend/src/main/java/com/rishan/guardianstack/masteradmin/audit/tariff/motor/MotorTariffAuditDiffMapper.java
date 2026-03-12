package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Computes a structured diff between two MotorTariff snapshots.
 * Called once per revision detail request; result is sent to the frontend as-is.
 */
@Component
public class MotorTariffAuditDiffMapper {

    public MotorTariffAuditDiffDTO compute(MotorTariffAuditSnapshot current,
                                           MotorTariffAuditSnapshot previous) {
        if (previous == null) {
            // First-ever revision — nothing to diff
            return MotorTariffAuditDiffDTO.builder()
                    .previousRevisionNumber(null)
                    .previousChangedBy(null)
                    .changedFields(Collections.emptyList())
                    .unchangedFields(Collections.emptyList())
                    .criticalChange(false)
                    .build();
        }

        List<MotorTariffAuditDiffDTO.DiffField> changed   = new ArrayList<>();
        List<MotorTariffAuditDiffDTO.DiffField> unchanged = new ArrayList<>();

        // ── Identity fields ───────────────────────────────────────────────
        diffString("tariffType",      "Tariff Type",       current.tariffType(),      previous.tariffType(),      changed, unchanged);
        diffString("groupOfVehicle",  "Group of Vehicle",  current.groupOfVehicle(),  previous.groupOfVehicle(),  changed, unchanged);
        diffString("typeOfVehicle",   "Type of Vehicle",   current.typeOfVehicle(),   previous.typeOfVehicle(),   changed, unchanged);
        diffString("category",        "Category / CC",     current.category(),        previous.category(),        changed, unchanged);

        // ── Financial fields ──────────────────────────────────────────────
        diffDecimal("ownDpBasic",    "Own DP Basic (BDT)", current.ownDpBasic(),    previous.ownDpBasic(),    changed, unchanged);
        diffDecimal("actLiability",  "Act Liability (BDT)", current.actLiability(), previous.actLiability(), changed, unchanged);

        // ── Rate fields (%) ───────────────────────────────────────────────
        diffPercent("fullInsValue", "Full Insurance Value (%)", current.fullInsValue(), previous.fullInsValue(), changed, unchanged);
        diffPercent("fire",         "Fire (%)",                 current.fire(),         previous.fire(),         changed, unchanged);
        diffPercent("theft",        "Theft (%)",                current.theft(),        previous.theft(),        changed, unchanged);
        diffPercent("cyclone",      "Cyclone (%)",              current.cyclone(),      previous.cyclone(),      changed, unchanged);
        diffPercent("earthquake",   "Earthquake (%)",           current.earthquake(),   previous.earthquake(),   changed, unchanged);

        // ── Status (critical) ─────────────────────────────────────────────
        diffBoolean("isActive", "Active Status", true, current.isActive(), previous.isActive(), changed, unchanged);

        boolean criticalChange = changed.stream().anyMatch(MotorTariffAuditDiffDTO.DiffField::critical);

        return MotorTariffAuditDiffDTO.builder()
                .previousRevisionNumber(previous.revisionNumber())
                .previousChangedBy(previous.changedBy())
                .changedFields(changed)
                .unchangedFields(unchanged)
                .criticalChange(criticalChange)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────

    private void diffBoolean(String name, String label, boolean isCritical,
                             Boolean curr, Boolean prev,
                             List<MotorTariffAuditDiffDTO.DiffField> changed,
                             List<MotorTariffAuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr.toString() : "null";
        String p = prev != null ? prev.toString() : "null";
        var f = MotorTariffAuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("BOOLEAN")
                .previousValue(p).currentValue(c)
                .critical(isCritical && !c.equals(p)).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private void diffString(String name, String label, String curr, String prev,
                            List<MotorTariffAuditDiffDTO.DiffField> changed,
                            List<MotorTariffAuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr : "";
        String p = prev != null ? prev : "";
        var f = MotorTariffAuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("STRING")
                .previousValue(p).currentValue(c).critical(false).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private void diffDecimal(String name, String label,
                             BigDecimal curr, BigDecimal prev,
                             List<MotorTariffAuditDiffDTO.DiffField> changed,
                             List<MotorTariffAuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr.toPlainString() : "—";
        String p = prev != null ? prev.toPlainString() : "—";
        var f = MotorTariffAuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("DECIMAL")
                .previousValue(p).currentValue(c).critical(false).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }

    private void diffPercent(String name, String label,
                             BigDecimal curr, BigDecimal prev,
                             List<MotorTariffAuditDiffDTO.DiffField> changed,
                             List<MotorTariffAuditDiffDTO.DiffField> unchanged) {
        String c = curr != null ? curr.toPlainString() : "—";
        String p = prev != null ? prev.toPlainString() : "—";
        var f = MotorTariffAuditDiffDTO.DiffField.builder()
                .fieldName(name).fieldLabel(label).fieldType("PERCENT")
                .previousValue(p).currentValue(c).critical(false).build();
        (c.equals(p) ? unchanged : changed).add(f);
    }
}