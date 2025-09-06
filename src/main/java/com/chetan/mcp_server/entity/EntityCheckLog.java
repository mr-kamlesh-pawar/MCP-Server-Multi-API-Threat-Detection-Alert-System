package com.chetan.mcp_server.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "entity_check_log")
public class EntityCheckLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String entity;
    private String entityType; // IP / DOMAIN
    private Integer abuseConfidenceScore;
    private Integer virustotalScore;
    private Boolean googleSafe;
    private Boolean isMalicious;
    private LocalDateTime checkedAt;
    private LocalDateTime lastReportedAt;
    private String issueId;
    private Double finalScore;


}