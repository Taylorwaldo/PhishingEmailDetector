package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.List;
import java.util.regex.Pattern;

/*
Purpose -> Analyzes the content of the email for suspicious language patterns often found in phishing attempts.

Logic
1. Loads phishing keywords from a resource file
2. Defines patterns for detecting requests for sensitive information
3. Check the subject and body for common phishing keywords
4. Counts how many different keywords appear in the body
5. Looks for patterns for requesting sensitive info
6. Examines writing style (excessive exclamation marks, ALL CAPS sections)
7. Accumulates a score based on these factors, with a max of 100
 */

/**
 * Analyzes email content for phishing language patterns
 */

public class ContentAnalyzer extends ThreatDetector {
    // Load phishing keywords from resource file
    private static final List<String> PHISHING_KEYWORDS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/phishing_keywords.txt");


    /*
    Patterns that suggest requests for sensitive information
    "Pattern" is the Java class used to compile and works with regex
    (?i)    ->  case-insensitive matching
    \\b     ->  word boundary, avoids partial matches (like a space)
    \\s     ->  means a whitespace character (space, tab, line break, etc.)
    *       ->  means "zero or more times"

    Phishing emails often do things like:

    - Hide keywords by inserting spaces or tabs

    - Use different letter cases

    - Add punctuation to confuse filters

    These regex patterns are trying to be smarter than simple keyword matching by accounting for common evasions.
     */

    private static final List<Pattern> SENSITIVE_INFO_PATTERNS = List.of(
            Pattern.compile("(?i)\\b(password|passcode)\\b"),
            Pattern.compile("(?i)\\b(credit\\s*card|card\\s*number)\\b"),
            Pattern.compile("(?i)\\b(bank\\s*account)\\b"),
            Pattern.compile("(?i)\\b(login|sign\\s*in)\\b"),
            Pattern.compile("(?i)\\b(verify your)\\b")
    );

    @Override
    public int analyze(Email email) {
        String subject = email.getSubject();
        String body = email.getBody();
        int score = 0;

        // Check subject for phishing keywords
        for (String keyword : PHISHING_KEYWORDS) {
            if (subject.toLowerCase().contains(keyword.toLowerCase())) {
                score += 20;
                break; // Only count once subject
            }
        }

        // Check body for phishing keywords
        int keywordCount = 0;
        for (String keyword : PHISHING_KEYWORDS) {
            if (body.toLowerCase().contains(keyword.toLowerCase())) {
                keywordCount++; // for each keyword found, increment by 1
            }
        }

        /*
        Scale keyword score based on how many were found.
        For each keyword found in the body, we multiply by 8 points.
        However, it caps the added score at 40 points, no matter how many keywords are found.
         */

        score += Math.min(40, keywordCount * 8);

        for (Pattern pattern : SENSITIVE_INFO_PATTERNS) {
            if (pattern.matcher(body).find()) {
                score += 15;
                break; // Only count once
            }
        }

        // Check for excessive use of urgent language or exclamation marks
        int exclamationCount = body.length() - body.replace("!", "").length();
        if (exclamationCount > 3) {
            score += 10;
        }

        /*
         Checks for ALL CAPS sections
         The regex ".*[A-Z]{10,}.*" works as follows:
         .*             ->  zero or more characters
         [A-Z]{10,}     ->  any uppercase letters from A to Z that appear 10 or more times in a row
         */
        if (body.matches(".*[A-Z]{10,}.*")) {
            score += 10;
        }

        // Normalize the score
        return Math.min(score, 100);
    }

}
