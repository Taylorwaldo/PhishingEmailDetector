/**
 *
 * @author Taylor Waldo, James Bostick, Bennett Marsee, Caitlyn Pillsbury, Caleb Walton
 * Date: 4/23/2025
 * Section: CSC-331-002
 * Purpose: To coordinate all the analyzers and process their scores to determine the final phishing score.
 *
 */

package com.waldotaylor.phishingdetector.main;

import com.waldotaylor.phishingdetector.analysis.*;
import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/*
Purpose -> The main orchestration class that coordinates all analyzers and calculates the final phishing score.

Logic ->
1. Maintains a map of analyzer objects with their weight factors
2. First runs the BodyAnalyzer to extract links and potential attachments
3. Then runs all other analyzers
4. Calculates a weighted average of all analyzer scores
5. Applies risk escalation for dangerous components
6. Applies risk multipliers for dangerous combinations
7. Generates a detailed color-coded report of the findings
 */

public class PhishingDetector {

        // The analyzers with their respective weights for the final score
    private static final Map<ThreatDetector, Double> analyzers = new HashMap<>();

    /**
     * Creates a new PhishingDetector with default analyzers and weights
     */
    public PhishingDetector() {
        initializeAnalyzers();
    }

    /**
     * Initializes all analyzers with their weights
     */
    public static void initializeAnalyzers() {
        analyzers.clear();
        // Add analyzers with adjusted weights (totaling 100%)
        analyzers.put(new SenderAnalyzer(), 0.15);    // 15% weight (decreased)
        analyzers.put(new HeaderAnalyzer(), 0.10);    // 10% weight (unchanged)
        analyzers.put(new BodyAnalyzer(), 0.05);      // 5% weight (unchanged)
        analyzers.put(new LinkAnalyzer(), 0.25);      // 25% weight (increased)
        analyzers.put(new ContentAnalyzer(), 0.25);   // 25% weight (increased)
        analyzers.put(new AttachmentAnalyzer(), 0.20); // 20% weight (slightly decreased)
    }

    /**
     * Reloads all analyzers (useful if detection rules are updated)
     */
    public void reloadAnalyzers() {
        initializeAnalyzers();
    }

    /**
     * Analyzes an email for phishing indicators
     *
     * @param email The email to analyze
     * @return A score from 0-100 indicating phishing probability
     */
    public static int analyzeEmail(Email email) {
        // First run the BodyAnalyzer to extract links and potential attachments
        // This needs to be done before other analyzers since they may need this data
        for (ThreatDetector analyzer : analyzers.keySet()) {
            if (analyzer instanceof BodyAnalyzer) {
                //example of polymorphism
                analyzer.analyze(email);
                break;
            }
        }

        // Now run all analyzers to get their scores
        double weightedScoreSum = 0;
        int maxIndividualScore = 0;

        for (Map.Entry<ThreatDetector, Double> entry : analyzers.entrySet()) {
            ThreatDetector analyzer = entry.getKey();
            Double weight = entry.getValue();

            // Skip BodyAnalyzer since we already ran it
            if (!(analyzer instanceof BodyAnalyzer)) {
                //example of polymorphism
                int score = analyzer.analyze(email);
                weightedScoreSum += score * weight;

                // Track the highest individual score
                maxIndividualScore = Math.max(maxIndividualScore, score);
            }
        }

        // Calculate the weighted average score
        int weightedScore = (int) Math.round(weightedScoreSum);

        // Risk escalation: If any individual analyzer reports very high risk,
        // ensure the overall score reflects that danger
        if (maxIndividualScore >= 85) { // Reduced threshold from 90
            // If any component scores ≥85, ensure overall score is at least 75
            weightedScore = Math.max(weightedScore, 75);
        } else if (maxIndividualScore >= 70) { // Reduced threshold from 80
            // If any component scores ≥70, ensure overall score is at least 60
            weightedScore = Math.max(weightedScore, 60);
        } else if (maxIndividualScore >= 50) { // New tier
            // If any component scores ≥50, ensure overall score is at least 45
            weightedScore = Math.max(weightedScore, 45);
        }

        // Apply multipliers for dangerous combinations
        weightedScore = applyRiskMultipliers(email, weightedScore);

        return Math.min(weightedScore, 100); // Cap at 100
    }

    /**
     * Applies risk multipliers for dangerous combinations of phishing indicators
     *
     * @param email The email being analyzed
     * @param baseScore The initial weighted score
     * @return The adjusted score after applying multipliers
     */
    public static int applyRiskMultipliers(Email email, int baseScore) {
        int finalScore = baseScore;

        // Check for dangerous combinations
        boolean hasDangerousAttachments = false;
        boolean asksForSensitiveInfo = false;
        boolean hasSuspiciousLinks = false;

        // Check attachments
        for (String attachment : email.getAttachments()) {
            String lower = attachment.toLowerCase();
            if (lower.endsWith(".exe") || lower.endsWith(".bat") ||
                    lower.endsWith(".js") || lower.endsWith(".vbs") ||
                    lower.endsWith(".scr") || lower.endsWith(".cmd") ||
                    (lower.contains(".") && lower.substring(lower.lastIndexOf(".")).contains("."))) {
                hasDangerousAttachments = true;
                break;
            }
        }

        // Check for sensitive info requests in body
        String body = email.getBody().toLowerCase();
        if (body.contains("password") || body.contains("credit card") ||
                body.contains("social security") || body.contains("bank account") ||
                body.contains("login") || body.contains("verify your") ||
                body.contains("update your account")) {
            asksForSensitiveInfo = true;
        }

        // Check for suspicious links
        for (String link : email.getLinks()) {
            String linkLower = link.toLowerCase();
            if (linkLower.contains("verify") || linkLower.contains("secure") ||
                    linkLower.contains("login") || linkLower.contains("account") ||
                    linkLower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*") ||
                    !linkLower.startsWith("https")) {
                hasSuspiciousLinks = true;
                break;
            }
        }

        // Apply multipliers for dangerous combinations
        if (hasDangerousAttachments && asksForSensitiveInfo) {
            finalScore = (int)(finalScore * 1.4); // 40% increase
        } else if (hasSuspiciousLinks && asksForSensitiveInfo) {
            finalScore = (int)(finalScore * 1.3); // 30% increase
        } else if (hasDangerousAttachments || (hasSuspiciousLinks && asksForSensitiveInfo)) {
            finalScore = (int)(finalScore * 1.2); // 20% increase
        }

        return Math.min(finalScore, 100); // Cap at 100
    }

    /**
     * Generates a detailed report about the phishing analysis
     *
     * @param email The analyzed email
     * @param phishingScore The calculated phishing score
     * @return A formatted report string
     */
    public static String generateReport(Email email, int phishingScore) {
        StringBuilder report = new StringBuilder();
        report.append("PHISHING EMAIL DETECTION REPORT\n");
        report.append("===============================\n\n");

        report.append("Email Details:\n");
        report.append("- Sender: ").append(email.getSender()).append("\n");
        report.append("- Subject: ").append(email.getSubject()).append("\n");
        report.append("- Body Length: ").append(email.getBody().length()).append(" characters\n");
        report.append("- Links Found: ").append(email.getLinks().size()).append("\n");
        report.append("- Attachments Found: ").append(email.getAttachments().size()).append("\n\n");

        report.append("Phishing Probability Score: ").append(phishingScore).append("/100").append("\n\n");

        // Interpret the score with color
        if (phishingScore < 15) { // Lowered from 20
            report.append("ASSESSMENT: ").append("This email appears to be SAFE. No significant phishing indicators detected.").append("\n");
        } else if (phishingScore < 40) { // Lowered from 50
            report.append("ASSESSMENT: ").append("This email has SOME SUSPICIOUS elements but is likely legitimate. Proceed with caution.").append("\n");
        } else if (phishingScore < 60) { // Lowered from 70
            report.append("ASSESSMENT: ").append("This email is MODERATELY SUSPICIOUS and may be a phishing attempt. Verify before taking any action.").append("\n");
        } else {
            report.append("ASSESSMENT: ").append("This email is HIGHLY SUSPICIOUS and likely a phishing attempt. Do not click links, download attachments, or respond with personal information.").append("\n");
        }

        // List suspicious elements
        if (phishingScore > 0) {
            report.append("\nSuspicious Elements:\n");

            // Run individual analyzers again to highlight issues
            for (ThreatDetector analyzer : analyzers.keySet()) {
                 //example of polymorphism   
                int score = analyzer.analyze(email);
                if (score > 0) {
                    if (analyzer instanceof SenderAnalyzer) {
                        report.append("- Sender issues detected (score: ").append(score).append(")\n");
                    } else if (analyzer instanceof HeaderAnalyzer) {
                        report.append("- Subject line contains suspicious language (score: ").append(score).append(")\n");
                    } else if (analyzer instanceof LinkAnalyzer && !email.getLinks().isEmpty()) {
                        report.append("- Suspicious links detected (score: ").append(score).append(")\n");

                        // Create a set to remove duplicates
                        Set<String> uniqueLinks = new HashSet<>(email.getLinks());

                        // Add appropriate warning level based on score
                        if (score >= 70) {
                            report.append("  ").append("WARNING: HIGHLY SUSPICIOUS LINKS FOUND:").append("\n");
                        } else if (score >= 40) {
                            report.append("  ").append("CAUTION: MODERATELY SUSPICIOUS LINKS FOUND:").append("\n");
                        } else if (score >= 15) {
                            report.append("  ").append("NOTE: SLIGHTLY SUSPICIOUS LINKS FOUND:").append("\n");
                        } else {
                            report.append("  Links found (low suspicion):\n");
                        }

                        for (String link : uniqueLinks) {
                            report.append("  - ").append(link).append("\n");

                            // Add specific warnings about this link
                            if (link.startsWith("http:") && !link.startsWith("https:")) {
                                report.append("    * Uses unsecured HTTP protocol\n");
                            }

                            if (link.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
                                report.append("    * Contains an IP address instead of a domain name (highly suspicious)\n");
                            }

                            // Extract domain from link
                            String domain = "";
                            try {
                                if (link.contains("://")) {
                                    domain = link.split("://")[1].split("/")[0];
                                } else {
                                    domain = link.split("/")[0];
                                }

                                // Remove port if present
                                if (domain.contains(":")) {
                                    domain = domain.split(":")[0];
                                }

                                // Check for misspelled domains
                                for (String legitimate : ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/legitimate_domains.txt")) {
                                    if (domain.contains(legitimate.substring(0, legitimate.length()-1)) &&
                                            !domain.equals(legitimate) &&
                                            !domain.endsWith("." + legitimate)) {
                                        report.append("    * May be mimicking legitimate domain: ").append(legitimate).append("\n");
                                        break;
                                    }
                                }

                                // Check against known suspicious domains
                                for (String suspicious : ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/suspicious_domains.txt")) {
                                    if (domain.toLowerCase().contains(suspicious.toLowerCase())) {
                                        report.append("    * Contains known suspicious domain: ").append(suspicious).append("\n");
                                        break;
                                    }
                                }

                                // Domain length check
                                if (domain.length() > 30) {
                                    report.append("    * Unusually long domain name\n");
                                }

                            } catch (Exception e) {
                                report.append("    * Malformed URL (unable to parse)\n");
                            }
                        }

                    } else if (analyzer instanceof ContentAnalyzer) {
                        report.append("- Content contains suspicious language or requests (score: ").append(score).append(")\n");

                        // Add details about what was found in the content
                        if (score >= 70) {
                            report.append("  ").append("ALERT: Highly suspicious content detected").append("\n");
                        }

                        // Check for common phishing phrases and highlight them
                        for (String keyword : ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/phishing_keywords.txt")) {
                            if (email.getBody().toLowerCase().contains(keyword.toLowerCase())) {
                                report.append("    * Contains suspicious phrase: \"").append(keyword).append("\"\n");
                                // Limit to a few examples to avoid overwhelming the report
                                if (report.toString().split("\\* Contains suspicious phrase").length > 5) {
                                    report.append("    * (Additional suspicious phrases found...)\n");
                                    break;
                                }
                            }
                        }

                    } else if (analyzer instanceof AttachmentAnalyzer && !email.getAttachments().isEmpty()) {
                        // Color-code based on attachment risk
                        report.append("- Potentially dangerous attachments detected (score: ")
                                .append(score).append(")\n");

                        report.append("  Attachments found:\n");
                        for (String attachment : email.getAttachments()) {
                            report.append("  - ").append(attachment).append("\n");

                            // Add warnings about specific attachments
                            String lowerAttachment = attachment.toLowerCase();

                            // Check for high-risk extensions
                            for (String ext : ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/high_risk_extensions.txt")) {
                                if (lowerAttachment.endsWith(ext.toLowerCase())) {
                                    report.append("    * ")
                                            .append("HIGH RISK: Contains executable or script extension (")
                                            .append(ext).append(")").append("\n");
                                    break;
                                }
                            }

                            // Check for medium-risk extensions
                            for (String ext : ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/medium_risk_extensions.txt")) {
                                if (lowerAttachment.endsWith(ext.toLowerCase())) {
                                    report.append("    * ")
                                            .append("MEDIUM RISK: Contains potentially risky file type (")
                                            .append(ext).append(")").append("\n");
                                    break;
                                }
                            }

                            // Check for double extensions
                            int lastDotIndex = lowerAttachment.lastIndexOf('.');
                            if (lastDotIndex > 0) {
                                String nameWithoutExtension = lowerAttachment.substring(0, lastDotIndex);
                                if (nameWithoutExtension.contains(".")) {
                                    report.append("    * ")
                                            .append("SUSPICIOUS: Contains multiple file extensions (possible disguised file)")
                                            .append("\n");
                                }
                            }
                        }
                    }
                }
            }
        }

        report.append("\nSafety Recommendations:\n");
        report.append("1. Verify the sender's email address carefully.\n");
        report.append("2. Hover over links before clicking to see where they really go.\n");
        report.append("3. Never provide sensitive information in response to an email.\n");
        report.append("4. Contact the supposed sender through official channels if unsure.\n");
        report.append("5. Check for grammar and spelling mistakes, which are common in phishing emails.\n");

        return report.toString();
    }
}
