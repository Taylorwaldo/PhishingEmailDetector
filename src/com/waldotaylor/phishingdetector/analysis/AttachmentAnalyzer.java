package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.List;

/*
Purpose -> Examines email attachments for potentially dangerous file types.

Logic:
1. Loads lists of high-risk and medium-risk file extensions from resource files
2. For each attachment
        -> Check if it has a high-risk extension
        -> If not, check if it has a medium-risk extension
        -> Looks for double extensions (e.g., file.txt.exe) which can be used to disguise malicious files
3. Takes the highest risk score from any attachment
 */

/**
 * Analyzes email attachments for suspicious file types
 */

public class AttachmentAnalyzer extends ThreatDetector {
    // Load high-risk file extensions from resource file
    private static final List<String> HIGH_RISK_EXTENSIONS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/high_risk_extensions.txt");

    // Load medium-risk file extensions from resource file
    private static final List<String> MEDIUM_RISK_EXTENSIONS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/medium_risk_extensions.txt");

    @Override
    public int analyze(Email email) {
        List<String> attachments = email.getAttachments();
        if (attachments.isEmpty()) {
            return 0; // No attachments to analyze
        }

        // Tracker
        int highestScore = 0;

        for (String attachment : attachments) {
            String lowerCaseAttachment = attachment.toLowerCase();
            int attachmentScore = 0;

            // Check for high-risk extensions
            for (String ext : HIGH_RISK_EXTENSIONS) {
                if (lowerCaseAttachment.endsWith(ext.toLowerCase())) {
                    attachmentScore = 80;
                }
            }

            // Check for medium-risk extensions
            if (attachmentScore == 0) {     // Only check if not already flagged as high-risk
                for (String ext : MEDIUM_RISK_EXTENSIONS) {
                    if (lowerCaseAttachment.endsWith(ext.toLowerCase())) {
                        attachmentScore = 40;
                        break;
                    }
                }
            }

            // Check for double extensions (e.g., file.txt.exe)
            int lastDotIndex = lowerCaseAttachment.lastIndexOf('.');

            if (lastDotIndex > 0) {
                String nameWithoutExtension = lowerCaseAttachment.substring(0, lastDotIndex);
                if (nameWithoutExtension.contains(".")) {
                    attachmentScore += 15;
                }
            }

            // Update highest score
            highestScore = Math.max(highestScore, attachmentScore);
        }

        return highestScore;
    }
}
