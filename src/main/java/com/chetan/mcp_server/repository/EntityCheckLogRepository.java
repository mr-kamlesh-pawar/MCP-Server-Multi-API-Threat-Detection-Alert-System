package com.chetan.mcp_server.repository;

import com.chetan.mcp_server.entity.EntityCheckLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EntityCheckLogRepository extends JpaRepository<EntityCheckLog, Long> {
    List<EntityCheckLog> findByIssueId(String issueId);
    boolean existsByEntityAndIssueId(String entity, String issueId);
}

