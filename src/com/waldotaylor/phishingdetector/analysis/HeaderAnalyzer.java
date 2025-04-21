package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.List;

/*
Purpose -> Examines email headers, focusing on the subject line and sender information.

Logic ->
1. Loads suspicious subject patterns from a resource file (using the same phishing keywords)
2. Checks the subject for these suspicious patterns
3. Looks for urgency indicators in the subject (exclamation marks)
4. Detects ALL CAPS usages in the subject
5. Analyzes the sender infomation for mismatches between display name and actual email domain.
        - This catches cases like "Bank of America  scammer@malicious.com"
 */

// checks SPF/DKIM headers, sender legitimacy

public class HeaderAnalyzer extends ThreatDetector {
    // Load suspicious subject patterns from resource file
    private static final List<String> SUSPICIOUS_SUBJECT_PATTERNS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/phishing_keywords.txt");

    @Override
    public int analyze(Email email) {
        String subject = email.getSubject();
        String sender = email.getSender();
        int score = 0;

        // Check for suspicious subject patterns
        for (String pattern : SUSPICIOUS_SUBJECT_PATTERNS) {
            if (subject.toLowerCase().contains(pattern.toLowerCase())) {
                score += 15;
                break; // Only count once
            }
        }

        // Check for urgency indicators in subject
        if (subject.contains("!")) {
            score += 5 * (subject.length() - subject.replace("!","").length());
        }

        // Check for ALL CAPS in the subject
        if (subject.equals(subject.toUpperCase()) && subject.length() > 10) { // Is the subject entirely uppercase? AND 10 characters +
            score += 20;
        }

        // Check for mismatches sender information
        if (sender.contains("<") && sender.contains(">")) {
            String displayName = sender.substring(0, sender.indexOf("<")).trim();                               // Extract everything before < → display name
            String emailAddress = sender.substring(sender.indexOf("<") + 1, sender.indexOf(">")).trim();        // Extract text between < and > → actual email address

            // Check if display name contains a different domain than the email address
            if (emailAddress.contains("@")) {
                String emailDomain = emailAddress.substring(emailAddress.lastIndexOf("@") + 1);
                if (displayName.toLowerCase().contains(".com") ||
                        displayName.toLowerCase().contains(".org") ||
                        displayName.toLowerCase().contains(".net")) {

                    // If display name contains a domain but it's not in the email domain.
                    if (!displayName.toLowerCase().contains(emailDomain.toLowerCase())) {
                        score += 40;
                    }
                }
            }
        }

        return Math.min(score, 100);

    }
}
