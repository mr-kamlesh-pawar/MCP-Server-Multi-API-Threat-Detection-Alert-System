package com.chetan.mcp_server.service;

import com.chetan.mcp_server.entity.EntityCheckLog;
import com.chetan.mcp_server.entity.JiraIssue;
import com.chetan.mcp_server.repository.EntityCheckLogRepository;
import com.chetan.mcp_server.repository.JiraIssueRepository;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MCPService {

    private final JiraIssueRepository jiraRepo;
    private final EntityCheckLogRepository logRepo;
    private final RestTemplate restTemplate = new RestTemplate();

    private static final Logger logger = LoggerFactory.getLogger(MCPService.class);

    @Value("${abuseipdb.api.key}")
    private String abuseApiKey;

    @Value("${virustotal.api.key}")
    private String virusTotalApiKey;

    @Value("${google.api.key}")
    private String googleApiKey;

    @Value("${jira.api.url}")
    private String jiraUrl;
    @Value("${jira.api.email}")
    private String jiraUser;
    @Value("${jira.api.token}")
    private String jiraToken;
    @Value("${jira.project.key}")
    private String jiraProjectKey;

    @Autowired
    private JavaMailSender mailSender;

    @Value("${alert.email.to}")
    private String alertEmail;

    public MCPService(JiraIssueRepository jiraRepo, EntityCheckLogRepository logRepo) {
        this.jiraRepo = jiraRepo;
        this.logRepo = logRepo;
    }

    // Main checker with duplicate prevention
    public void checkAndLogEntity(String entity, String entityType, String issueId) {

        // Already checked?
        if (logRepo.existsByEntityAndIssueId(entity, issueId)) {
            logger.info("🔹 Already checked -> {} [{}] for issue {}", entity, entityType, issueId);
            return;
        }

        EntityCheckLog log = new EntityCheckLog();
        log.setEntity(entity);
        log.setEntityType(entityType);
        log.setCheckedAt(LocalDateTime.now());
        log.setIssueId(issueId);

        // AbuseIPDB (only for IPs)
        if ("IP".equalsIgnoreCase(entityType)) {
            try {
                String url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + entity + "&maxAgeInDays=90";
                HttpHeaders headers = new HttpHeaders();
                headers.set("Key", abuseApiKey);
                headers.set("Accept", "application/json");

                HttpEntity<String> request = new HttpEntity<>(headers);
                ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);

                Map data = (Map) response.getBody().get("data");
                log.setAbuseConfidenceScore((Integer) data.get("abuseConfidenceScore"));
                System.out.println(data.get("abuseConfidenceScore") + " abuseConfidenceScore ");
                if (data.get("lastReportedAt") != null) {
                    try {
                        OffsetDateTime odt = OffsetDateTime.parse((String) data.get("lastReportedAt"),
                                DateTimeFormatter.ISO_OFFSET_DATE_TIME);
                        log.setLastReportedAt(odt.toLocalDateTime());
                    } catch (Exception ignored) {}
                }
            } catch (Exception e) {
                log.setAbuseConfidenceScore(0);
            }
        } else {
            log.setAbuseConfidenceScore(0);
        }

        // VirusTotal (IP + Domain)
        try {
            String url = ("IP".equalsIgnoreCase(entityType))
                    ? "https://www.virustotal.com/api/v3/ip_addresses/" + entity
                    : "https://www.virustotal.com/api/v3/domains/" + entity;

            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", virusTotalApiKey);

            HttpEntity<String> request = new HttpEntity<>(headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);

            Map data = (Map) response.getBody().get("data");
            Map attributes = (Map) data.get("attributes");
            Map lastAnalysisStats = (Map) attributes.get("last_analysis_stats");

            log.setVirustotalScore((Integer) lastAnalysisStats.get("malicious"));
            System.out.println("hello");
        } catch (Exception e) {
            log.setVirustotalScore(0);
        }

        // Google Safe Browsing (IP + Domain)
        try {
            String url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + googleApiKey;
            String body = "{ \"client\": {\"clientId\": \"mcp-app\",\"clientVersion\": \"1.0\"}, "
                    + "\"threatInfo\": {\"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\"], "
                    + "\"platformTypes\": [\"ANY_PLATFORM\"], "
                    + "\"threatEntryTypes\": [\"URL\"], "
                    + "\"threatEntries\": [{\"url\": \"" + entity + "\"}]}}";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> request = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.POST, request, Map.class);

            boolean unsafe = response.getBody() != null && response.getBody().containsKey("matches");
            log.setGoogleSafe(!unsafe);
        } catch (Exception e) {
            log.setGoogleSafe(true);
        }


        // Final Decision using weighted average
        double abuseScore = log.getAbuseConfidenceScore() != null ? log.getAbuseConfidenceScore() : 0;
        double virusScore = log.getVirustotalScore() != null ? log.getVirustotalScore() : 0;

// Normalize VirusTotal (assume max possible malicious detections = 14 for example, adjust if needed)
        double maxVirusScore = 14.0;
        virusScore = (virusScore / maxVirusScore) * 100;

// Google Safe: 0 = safe, 1 = unsafe
        double googleScore = log.getGoogleSafe() != null && !log.getGoogleSafe() ? 100 : 0;

// Assign weights
        double abuseWeight = 0.4;
        double virusWeight = 0.4;
        double googleWeight = 0.2;

// Weighted average calculation
        double finalScore = (abuseScore * abuseWeight) + (virusScore * virusWeight) + (googleScore * googleWeight);

// Threshold for malicious
        double threshold = 50; // tweak as needed
        boolean isMalicious = finalScore >= threshold;

        log.setIsMalicious(isMalicious);
        log.setFinalScore(finalScore);
        logRepo.save(log);

        if (isMalicious) {
            logger.warn("⚠️ Malicious detected -> {} [{}], Final Score: {}", entity, entityType, finalScore);
            sendAlertEmail(log);
        } else {
            logger.info("✅ Safe -> {} [{}], Final Score: {}", entity, entityType, finalScore);
        }

    }

    // Jira Issues Fetch
    public void fetchAndSaveJiraIssues() {
        try {
            // GET URL with query params
            String searchUrl = jiraUrl
                    + "?jql=project=" + jiraProjectKey
                    + "&fields=key,summary,status"
                    + "&maxResults=50";  // as per working cURL

            String auth = jiraUser + ":" + jiraToken;
            String base64Creds = Base64.getEncoder().encodeToString(auth.getBytes());

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Basic " + base64Creds);
            headers.set("Accept", "application/json");

            HttpEntity<String> request = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(searchUrl, HttpMethod.GET, request, Map.class);

            Map responseBody = response.getBody();
            if (responseBody != null && responseBody.containsKey("issues")) {
                List<Map<String, Object>> issues = (List<Map<String, Object>>) responseBody.get("issues");

                for (Map<String, Object> issue : issues) {
                    Map<String, Object> fields = (Map<String, Object>) issue.get("fields");

                    String issueId = (String) issue.get("id");
                    String summary = (String) fields.get("summary");

                    if (!jiraRepo.existsById(issueId)) {
                        JiraIssue newIssue = new JiraIssue();
                        newIssue.setIssueId(issueId);
                        newIssue.setSummary(summary);
                        jiraRepo.save(newIssue);

                        checkEntitiesForIssue(newIssue);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("❌ Jira fetch error: {}", e.getMessage(), e);
        }
    }




    // Extract entities and check them
    private void checkEntitiesForIssue(JiraIssue issue) {
        String summary = issue.getSummary();

        // IP extraction
        Pattern ipPattern = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        Matcher ipMatcher = ipPattern.matcher(summary);
        while (ipMatcher.find()) {
            String ip = ipMatcher.group();
            checkAndLogEntity(ip, "IP", issue.getIssueId());
        }

        // Domain extraction
        Pattern domainPattern = Pattern.compile("([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        Matcher domainMatcher = domainPattern.matcher(summary);
        while (domainMatcher.find()) {
            String domain = domainMatcher.group();
            checkAndLogEntity(domain, "DOMAIN", issue.getIssueId());
        }
    }

    public List<JiraIssue> getAllIssuesFromDb() {
        return jiraRepo.findAll();
    }

    private void sendAlertEmail(EntityCheckLog log) {
        try {
            String entity = log.getEntity();
            String entityType = log.getEntityType();
            double finalScore = log.getFinalScore();

            String subject = "⚠️ Malicious Entity Detected: " + entity;

            // HTML body with inline CSS and subtle animation
            String htmlBody = "<!DOCTYPE html>"
                    + "<html>"
                    + "<head>"
                    + "<style>"
                    + "  body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }"
                    + "  .card { background-color: #fff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 600px; margin: auto; animation: fadeIn 1s ease-in-out; }"
                    + "  h2 { color: #d32f2f; }"
                    + "  p { font-size: 14px; color: #333; }"
                    + "  .score { font-weight: bold; color: #d32f2f; }"
                    + "  @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }"
                    + "</style>"
                    + "</head>"
                    + "<body>"
                    + "<div class='card'>"
                    + "<h2>⚠️ Malicious Entity Detected!</h2>"
                    + "<p><strong>Entity:</strong> " + entity + "</p>"
                    + "<p><strong>Type:</strong> " + entityType + "</p>"
                    + "<p><strong>AbuseIPDB Score:</strong> " + log.getAbuseConfidenceScore() + "</p>"
                    + "<p><strong>VirusTotal Score:</strong> " + log.getVirustotalScore() + "</p>"
                    + "<p><strong>Google Safe Browsing:</strong> " + (log.getGoogleSafe() ? "Safe" : "Unsafe") + "</p>"
                    + "<p><strong>Final Weighted Score:</strong> <span class='score'>" + finalScore + "</span></p>"
                    + "<p><strong>Issue ID:</strong> " + log.getIssueId() + "</p>"
                    + "<p><strong>Checked At:</strong> " + log.getCheckedAt() + "</p>"
                    + "<p style='color:#555;font-size:12px;margin-top:10px;'>This is an automated alert from MCP Server</p>"
                    + "</div>"
                    + "</body>"
                    + "</html>";

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(alertEmail);
            helper.setSubject(subject);
            helper.setText(htmlBody, true); // true = HTML

            mailSender.send(message);
            logger.info("✅ Alert email sent for entity {}", entity);
        } catch (Exception e) {
            logger.error("❌ Failed to send alert email: {}", e.getMessage());
        }
    }

}
