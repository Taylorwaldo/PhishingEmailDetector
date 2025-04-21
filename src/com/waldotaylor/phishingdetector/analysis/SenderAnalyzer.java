


package com.waldotaylor.phishingdetector.analysis;

import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.List;
import java.util.Arrays;
import java.util.regex.Pattern;

/*
Purpose -> Analyzes the sender's email address for suspicious patterns that might
indicate phishing

Logic -->
1. Loads a list of suspicious domain from a resource file
2. Validates if the email format is correct
3. Extracts the domain part of the email address
4. Checks the domain against the list of known suspicious domain
5. Looks for numeric characters in the domain (could indicate temp domains, trail ran 10minutemail.com, temp-mail.org)
6. Checks for unusually long domain names
7. Returns a cumulative score based on these checks

 */

public class SenderAnalyzer extends ThreatDetector {
    // List of suspicious domains from resource file
    private static final List<String> SUSPICIOUS_DOMAINS =
            ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/suspicious_domains.txt");

    // Regex pattern for basic email validation
    /*
        regex
        "^" -> Start of the string

        [A-Za-z0-9+_.-]+ (before @)
        A-Z         -> uppercase letters
        a-z         -> lowercase letters
        0-9         -> numbers
        +,_,.,-     -> common symbols in emails

        "@"         -> Literal @ symbol
        (.+)        -> captures the goods aka the domain etc gmail.com, uncw.edu
        $           -> end of string

        Recap -> " Creates a regular expression pattern for basic email validation."

        example:
        user.name123@gmail.com      matches         domain captured: gmail.com
        abc+xyz@totally-legit.net   matches         domain captured: totally-legit.net
        bademail@                   invalid         none
        @nodomain.com               invalid         none

        source - https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html
         */
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    @Override
    public int analyze(Email email) {
        String sender = email.getSender();
        int score = 0;

        // Check if sender email is in a valid format
        if (!EMAIL_PATTERN.matcher(sender).matches()) {
            score += 50; // Invalid email format is highly suspicious
            return score;
        }

        // Extract domain from email
        String domain = sender.substring(sender.lastIndexOf('@') + 1);

        // Check against suspicious domains
        /*
        -> .equals(...): checks if two strings are exactly the same.
        -> .endsWith(...): checks if a string ends with a certain substring.
        -> ||: logical OR: this means either condition being true will trigger the block.
        -> .toLowerCase(): makes both strings lowercase so the check is case-insensitive.
         */
        for (String suspiciousDomain : SUSPICIOUS_DOMAINS) {
            if (domain.toLowerCase().equals(suspiciousDomain.toLowerCase()) ||
                    domain.toLowerCase().endsWith("." + suspiciousDomain.toLowerCase())) {
                score += 60;
                break; // Stop checking more domains; one match is enough.
            }
        }

        // Check for numeric characters in domain (may indicate a temp domain)
        /*
        regex -> (".*\\d.*")
        "\d" -> any digit 0-9, another \ because... java. Backslashes must be escaped
        "*" -> means zero or more of any character
        Recap -> "The string contains at least one digit, anywhere in it."

        example:
        securelogin.com.... doesn't match either regex so it DOES NOT add 15
        email22.net.... matches regex: adds 15

        source - https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html
         */
        if (domain.matches(".*\\d.*")) {
            score += 15;
        }

        // Check for unusually long domain names
        if (domain.length() > 30) {
            score += 10;
        }

        return Math.min(score, 100); // returns the smaller value between score and 100, ensures it doesn't go past 100

    }
}
