package com.waldotaylor.phishingdetector.main;

import com.waldotaylor.phishingdetector.analysis.*;
import com.waldotaylor.phishingdetector.model.Email;

import java.util.HashMap;
import java.util.Map;

/*
Purpose -> The main orchestration class that coordinates all analyzers and calculates the final phishing score.

Logic ->
1. Maintains a map of analyzer objects with their weight factors
2. First runs the BodyAnalyzer to extract links and potential attachments
3. Then runs all other analyzers
4. Calculates a weighted average of all analyzer scores
5. Generates a detailed report of the findings
 */

public class PhishingDetector {
    // The analyzers with their respective weights for the final score
    private final Map<ThreatDetector, Double> analyzers = new HashMap<>();

    /**
     * Creates a new PhishingDetector with default analyzers and weights
     */
    public PhishingDetector() {
        initializeAnalyzers();
    }

    /**
     * Initializes all analyzers with their weights
     */
    private void initializeAnalyzers() {
        analyzers.clear();
        // Add analyzers with weights (totaling 100%)
        analyzers.put(new SenderAnalyzer(), 0.25);    // 25% weight
        analyzers.put(new HeaderAnalyzer(), 0.10);    // 10% weight
        analyzers.put(new BodyAnalyzer(), 0.05);      // 5% weight - mainly for extraction
        analyzers.put(new LinkAnalyzer(), 0.25);      // 25% weight
        analyzers.put(new ContentAnalyzer(), 0.20);   // 20% weight
        analyzers.put(new AttachmentAnalyzer(), 0.15); // 15% weight
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
    public int analyzeEmail(Email email) {
        // First run the BodyAnalyzer to extract links and potential attachments
        // This needs to be done before other analyzers since they may need this data
        for (ThreatDetector analyzer : analyzers.keySet()) {
            if (analyzer instanceof BodyAnalyzer) {
                analyzer.analyze(email);
                break;
            }
        }

        // Now run all analyzers to get their scores
        double weightedScoreSum = 0;
        for (Map.Entry<ThreatDetector, Double> entry : analyzers.entrySet()) {
            ThreatDetector analyzer = entry.getKey();
            Double weight = entry.getValue();

            // Skip BodyAnalyzer since we already ran it
            if (!(analyzer instanceof BodyAnalyzer)) {
                int score = analyzer.analyze(email);
                weightedScoreSum += score * weight;
            }
        }

        // Round to the nearest integer
        return (int) Math.round(weightedScoreSum);
    }

    /**
     * Generates a detailed report about the phishing analysis
     *
     * @param email The analyzed email
     * @param phishingScore The calculated phishing score
     * @return A formatted report string
     */
    public String generateReport(Email email, int phishingScore) {
        StringBuilder report = new StringBuilder();
        report.append("PHISHING EMAIL DETECTION REPORT\n");
        report.append("===============================\n\n");

        report.append("Email Details:\n");
        report.append("- Sender: ").append(email.getSender()).append("\n");
        report.append("- Subject: ").append(email.getSubject()).append("\n");
        report.append("- Body Length: ").append(email.getBody().length()).append(" characters\n");
        report.append("- Links Found: ").append(email.getLinks().size()).append("\n");
        report.append("- Attachments Found: ").append(email.getAttachments().size()).append("\n\n");

        report.append("Phishing Probability Score: ").append(phishingScore).append("/100\n\n");

        // Interpret the score
        if (phishingScore < 20) {
            report.append("ASSESSMENT: This email appears to be SAFE. No significant phishing indicators detected.\n");
        } else if (phishingScore < 50) {
            report.append("ASSESSMENT: This email has SOME SUSPICIOUS elements but is likely legitimate. Proceed with caution.\n");
        } else if (phishingScore < 70) {
            report.append("ASSESSMENT: This email is MODERATELY SUSPICIOUS and may be a phishing attempt. Verify before taking any action.\n");
        } else {
            report.append("ASSESSMENT: This email is HIGHLY SUSPICIOUS and likely a phishing attempt. Do not click links, download attachments, or respond with personal information.\n");
        }

        // List suspicious elements
        if (phishingScore > 0) {
            report.append("\nSuspicious Elements:\n");

            // Run individual analyzers again to highlight issues
            for (ThreatDetector analyzer : analyzers.keySet()) {
                int score = analyzer.analyze(email);
                if (score > 0) {
                    if (analyzer instanceof SenderAnalyzer) {
                        report.append("- Sender issues detected (score: ").append(score).append(")\n");
                    } else if (analyzer instanceof HeaderAnalyzer) {
                        report.append("- Subject line contains suspicious language (score: ").append(score).append(")\n");
                    } else if (analyzer instanceof LinkAnalyzer && !email.getLinks().isEmpty()) {
                        report.append("- Suspicious links detected (score: ").append(score).append(")\n");
                        report.append("  Links found:\n");
                        for (String link : email.getLinks()) {
                            report.append("  - ").append(link).append("\n");
                        }
                    } else if (analyzer instanceof ContentAnalyzer) {
                        report.append("- Content contains suspicious language or requests (score: ").append(score).append(")\n");
                    } else if (analyzer instanceof AttachmentAnalyzer && !email.getAttachments().isEmpty()) {
                        report.append("- Potentially dangerous attachments detected (score: ").append(score).append(")\n");
                        report.append("  Attachments found:\n");
                        for (String attachment : email.getAttachments()) {
                            report.append("  - ").append(attachment).append("\n");
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

