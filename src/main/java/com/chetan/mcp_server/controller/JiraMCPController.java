package com.chetan.mcp_server.controller;

import com.chetan.mcp_server.service.MCPService;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/api/mcp")
public class JiraMCPController {

    private final MCPService mcpService;

    public JiraMCPController(MCPService mcpService) { this.mcpService = mcpService; }

    @GetMapping("/issues")
    public void getAllIssues() {
        mcpService.fetchAndSaveJiraIssues();
    }
}

