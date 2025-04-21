package com.waldotaylor.phishingdetector.analysis;

import com.waldotaylor.phishingdetector.model.Email;
import com.waldotaylor.phishingdetector.util.ResourceLoader;

import java.util.List;

/*
Purpose -> Analyzes links in the email to detect suspicious URLs that might be phishing attempts.

Logic -->
1. Loads lists of suspicious and legitimate domains from resource files
2. For each link in the email:
        -> Checks if it uses HTTP instead of HTTPS (less secure) "Learned that in CSC 344"
        -> Looks for IP addresses in URLs (suspicious)
        -> Extracts and analyzes the domain portion
        -> Checks against known suspicious domains
        -> Looks for domains that try to mimic legitimate sites
        -> Checks for unusually long domain names
        -> Examines for excessive special characters
3. Takes the highest individual link score
4. Ensures the final score doesn't exceed 100
 */

/**
 * Analyzes links in the email for suspicious patterns
 */

public class LinkAnalyzer extends ThreatDetector {
    // Load suspicious domains from the resource file
    private static final List<String> SUSPICIOUS_DOMAINS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/suspicious_domains.txt");

    // Load legitimate domains from the resource file
    private static final List<String> LEGITIMATE_DOMAINS = ResourceLoader.loadResourceAsList("/com/waldotaylor/phishingdetector/resources/legitimate_domains.txt");

    @Override
    public int analyze(Email email) {
        List<String> links = email.getLinks();
        if (links.isEmpty()) {
            return 0;       // No links to analyze, threat regarding links is "0"
        }

        // Tracker
        int totalScore = 0;



        for (String link : links) {
            int linkScore = 0;

            // Check if URL contains "http" without "s" (not secure)
            if (link.startsWith("http:") && !link.startsWith("https:")) {
                linkScore += 25;
            }

            /*
            Check for IP addresses in URLs via Regex Pattern

            .*          -> Matches any characters (the dot), any number of times (before and after the IP) (the asterisk)
            \\d{1.3}    -> A number between 1 and 3 digits (like 1, 99, 225)
            \\.         -> literal period, double escape needed
            Repeat 4 times forming the IP address

            Recap       -> “Find any text that contains an IP address somewhere in it”
            Examples:
            http://192.168.0.1/login        ✓
            https://8.8.8.8/suspicious      ✓
            https://google.com              ⨉

             */
            if (link.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
                linkScore += 50;
            }

            // Extract domain from URL
            String domain = "";
            try {
                if (link.contains("://")) {
                    domain = link.split("://")[1].split("/")[0];
                } else {
                    domain = link.split("/")[0];
                }

                // Remove port information if present
                if (domain.contains(":")) {
                    domain = domain.split(":")[0];
                }

                // Remove port info if present
                if (domain.contains(":")) {
                    domain = domain.split(":")[0];
                }

                // Check against suspicious domains
                for (String suspiciousDomain : SUSPICIOUS_DOMAINS) {
                    if (domain.toLowerCase().contains(suspiciousDomain.toLowerCase())) {
                        linkScore += 25;
                        break;
                    }
                }

                // Check for deceptive domains that look like legitimate ones
                for (String legitimate : LEGITIMATE_DOMAINS) {
                    if (domain.contains(legitimate) && !domain.equals(legitimate) && !domain.endsWith("." + legitimate)) {
                        linkScore += 40;
                        break;
                    }
                }

                // Check for unusually long domain names
                if (domain.length() > 30) {
                    linkScore += 10;
                }
            } catch (Exception e) {
                // If we can't parse the URL, it's sus
                linkScore += 20;
            }

            // URLs with many special characters
            if (link.replaceAll("[A-Za-z0-9:/.-]", "").length() > 5) {
                linkScore += 15;
            }

            totalScore = Math.max(totalScore, linkScore);

        }

        // Return the highest score from any link
        return Math.min(totalScore, 100);
    }
}