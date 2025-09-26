package com.chetan.mcp_server.config;

import com.chetan.mcp_server.service.MCPService;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
public class SchedulerConfig {

    private final MCPService mcpService;

    public SchedulerConfig(MCPService mcpService) {
        this.mcpService = mcpService;
    }

    @Scheduled(fixedRate = 60000) // every 1 min
    public void autoCheck() {
        mcpService.fetchAndSaveJiraIssues();
    }
}
