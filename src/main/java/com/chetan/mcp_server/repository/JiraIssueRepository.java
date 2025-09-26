package com.chetan.mcp_server.repository;

import com.chetan.mcp_server.entity.JiraIssue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


public interface JiraIssueRepository extends JpaRepository<JiraIssue, String> {


}

