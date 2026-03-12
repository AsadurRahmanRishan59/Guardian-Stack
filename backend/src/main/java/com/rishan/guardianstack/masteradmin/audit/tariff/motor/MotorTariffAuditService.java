package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import com.rishan.guardianstack.masteradmin.audit.tariff.motor.filter.MotorTariffAuditFilterRequest;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.Optional;

public interface MotorTariffAuditService {

    /** LEFT PANEL — paginated slim timeline items */
    Page<MotorTariffAuditTimelineItemDTO> getTimelineItems(MotorTariffAuditFilterRequest filter);

    /** RIGHT PANEL — full snapshot + diff for a single revision */
    Optional<MotorTariffAuditDTO> getRevisionDetail(Integer tariffKey, Long revisionNumber);

    /** DRILL-DOWN — all revisions for one tariff entry */
    List<MotorTariffAuditTimelineItemDTO> getTariffTimeline(Integer tariffKey);
}