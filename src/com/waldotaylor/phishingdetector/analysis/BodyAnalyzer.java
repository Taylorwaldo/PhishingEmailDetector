package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


/*
Purpose -> Extracts links and potential attachments from the email body and performs initial content analysis.

Logic ->
1. Uses regex patterns to find and extract all URLs in the Body
2. Adds extracted URLs to the email object
3. Looks for mentions of attachment in the text
4. Checks for suspicious language patterns (poor grammar, generic greetings)
5. Examines formatting indicators
 */

public class BodyAnalyzer extends ThreatDetector {
    /*
    Pattern to extract URLs from body text
    Regex explanation..
    (https?://|www\\.)                  ->  match "http://", "https://", or "www."
    [-a-zA-Z0-9@:%._\\+~#=]{1,256}      ->  top-level domain like .com, .org, etc.
    \\b(...)                            ->  match the rest of the URL path after the domain
     */
    private static final Pattern URL_PATTERN =
            Pattern.compile("(https?://|www\\.)[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)");

    /*
    Pattern to potentially identify attachments mentions in the body
    Regex explanation..
    (?i)                                                        ->  case-insensitive (so it matches Attached, attachment, etc.)
    (attached|attachment|file|document|pdf|doc|xlsx|zip)        ->  one of these keywords
    \\s+                                                        ->  at least one space after the keyword
    [^\\s.,;:!?]{1,50}                                          ->  then match 1–50 characters that don’t include punctuation or spaces
            - this picks up files like eg "pdf secure_invoice.zip"
     */
    private static final Pattern ATTACHMENT_PATTERN =
            Pattern.compile("(?i)(attached|attachment|file|document|pdf|doc|xlsx|zip)\\s+[^\\s.,;:!?]{1,50}");

    @Override
    public int analyze(Email email) {
        String body = email.getBody();
        int score = 0;

        // Extract URLs from body and add them to the email object
        Matcher urlMatcher = URL_PATTERN.matcher(body);
        while (urlMatcher.find()) {
            String url = urlMatcher.group();
            email.addLink(url);
        }

        // Look for potential attachments mentioned in the body
        Matcher attachmentMatcher = ATTACHMENT_PATTERN.matcher(body);
        while (attachmentMatcher.find()) {
            String potentialAttachment = attachmentMatcher.group();

            // Check if this mentions a common file extension
            if (potentialAttachment.toLowerCase().contains(".pdf") ||
                    potentialAttachment.toLowerCase().contains(".doc") ||
                    potentialAttachment.toLowerCase().contains(".xls") ||
                    potentialAttachment.toLowerCase().contains(".zip") ||
                    potentialAttachment.toLowerCase().contains(".exe")) {

                // Add it to the attachments list if it's not already there
                if (!email.getAttachments().contains(potentialAttachment)) {
                    email.addAttachment(potentialAttachment);
                }
            }
        }

        // Check for inconsistencies in the email body

        // Poor grammar or spelling can indicate phishing
        if (body.contains("your account") && body.contains("needs updates")) {
            score += 15;
        }

        // Check for text with different formating (common in phishing according to reddit)
        // This is simplified since we can't check HTML in plain text
        if (body.contains("_") && body.contains("*")) {
            score += 5;
        }

        // Check for greetings that don't use the recipient's/user input's name (generic)
        if (body.startsWith("Dear Customer") || body.startsWith("Dear User") ||
                body.startsWith("Dear Sir") || body.startsWith("Dear Madam") ||
                body.startsWith("Dear Account Holder")) {
            score += 15;
        }

        return Math.min(score, 100);
    }


}
