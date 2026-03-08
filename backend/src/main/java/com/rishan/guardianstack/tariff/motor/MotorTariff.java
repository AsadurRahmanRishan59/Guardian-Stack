package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.core.domain.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import org.hibernate.envers.Audited;

import java.math.BigDecimal;

/**
 * Entity representing the regulated Motor Insurance Tariff for Bangladesh.
 * Managed by Master Admin. Audited via Hibernate Envers.
 */
@Entity
@Table(name = "gs_motor_tariff", uniqueConstraints = {
        @UniqueConstraint(name = "uk_gs_vehicle_combo", columnNames = {
                "tariff_type", "group_of_vehicle", "type_of_vehicle", "category"
        })
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Audited
public class MotorTariff extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "tariff_key")
    private Long tariffKey;

    @NotBlank(message = "Tariff type is required (e.g., Private Vehicle, Motor Cycle)")
    @Size(max = 50, message = "Tariff type cannot exceed 50 characters")
    @Pattern(regexp = "Private Vehicle|Motor Cycle|Commercial Vehicle", message = "Tariff type must be one of: Private Vehicle, Motor Cycle, Commercial Vehicle")
    @Column(name = "tariff_type", length = 50, nullable = false)
    private String tariffType;

    @NotBlank(message = "Group of vehicle is required (e.g., Passenger Vehicle)")
    @Size(max = 500, message = "Group name is too long")
    @Column(name = "group_of_vehicle", length = 500, nullable = false)
    private String groupOfVehicle;

    @NotBlank(message = "Type of vehicle description is required")
    @Size(max = 500, message = "Type description is too long")
    @Column(name = "type_of_vehicle", length = 500, nullable = false)
    private String typeOfVehicle;

    @NotBlank(message = "Category/CC range is required (e.g., Upto 1300 CC)")
    @Size(max = 500, message = "Category description is too long")
    @Column(name = "category", length = 500, nullable = false)
    private String category;

    @NotNull(message = "Own Damage Basic Premium is required")
    @DecimalMin(value = "0.0", message = "Basic premium cannot be negative")
    @Digits(integer = 8, fraction = 2, message = "Basic premium must be a valid amount (up to 8 digits and 2 decimals)")
    @Column(name = "own_dp_basic", precision = 10, scale = 2, nullable = false)
    private BigDecimal ownDpBasic;

    @NotNull(message = "Full Insurance Value rate (%) is required")
    @DecimalMin(value = "0.0", message = "Rate cannot be negative")
    @DecimalMax(value = "100.0", message = "Rate cannot exceed 100%")
    @Digits(integer = 3, fraction = 2, message = "Rate must be a valid percentage (e.g., 2.65)")
    @Column(name = "full_ins_value", precision = 5, scale = 2, nullable = false)
    private BigDecimal fullInsValue;

    @NotNull(message = "Act Liability amount is required")
    @DecimalMin(value = "0.0", message = "Act Liability cannot be negative")
    @Digits(integer = 8, fraction = 2, message = "Liability amount must be a valid currency format")
    @Column(name = "act_liability", precision = 10, scale = 2, nullable = false)
    private BigDecimal actLiability;

    @NotNull(message = "Fire rate is required")
    @Digits(integer = 3, fraction = 2, message = "Fire rate must be a valid percentage")
    @Column(name = "fire", precision = 5, scale = 2, nullable = false)
    private BigDecimal fire;

    @NotNull(message = "Theft rate is required")
    @Digits(integer = 3, fraction = 2, message = "Theft rate must be a valid percentage")
    @Column(name = "theft", precision = 5, scale = 2, nullable = false)
    private BigDecimal theft;

    @NotNull(message = "Cyclone rate is required")
    @Digits(integer = 3, fraction = 2, message = "Cyclone rate must be a valid percentage")
    @Column(name = "cyclone", precision = 5, scale = 2, nullable = false)
    private BigDecimal cyclone;

    @NotNull(message = "Earthquake rate is required")
    @Digits(integer = 3, fraction = 2, message = "Earthquake rate must be a valid percentage")
    @Column(name = "earthquake", precision = 5, scale = 2, nullable = false)
    private BigDecimal earthquake;

    @Builder.Default
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;
}