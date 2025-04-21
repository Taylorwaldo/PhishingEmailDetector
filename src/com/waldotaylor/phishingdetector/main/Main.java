/*
in the console mode
java com.waldotaylor.phishingdetector.main.Main

GUI mode
java com.waldotaylor.phishingdetector.main.PhishingDetectorApplication
 */


package com.waldotaylor.phishingdetector.main;

import com.waldotaylor.phishingdetector.model.Email;

import java.util.Scanner;

/**
 * Console application entry point
 * Provides a command-line interface for the phishing detector
 */
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        PhishingDetector detector = new PhishingDetector();

        System.out.println("PHISHING EMAIL DETECTOR");
        System.out.println("======================");
        System.out.println("Enter the email details to analyze for phishing indicators.");

        // Get sender email
        System.out.print("\nEnter sender email address: ");
        String sender = scanner.nextLine();

        // Get subject
        System.out.print("Enter email subject: ");
        String subject = scanner.nextLine();

        // Get body
        System.out.println("\nEnter email body (Type 'END' on a new line when finished):");
        StringBuilder bodyBuilder = new StringBuilder();
        String line;
        while (true) {
            line = scanner.nextLine();
            if (line.equals("END")) {
                break;
            }
            bodyBuilder.append(line).append("\n");
        }
        String body = bodyBuilder.toString();

        // Create Email object
        Email email = new Email(sender, subject, body);

        // Ask for attachments
        System.out.print("\nDoes the email have attachments? (yes/no): ");
        if (scanner.nextLine().toLowerCase().startsWith("y")) {
            System.out.println("Enter attachment filenames (one per line, Type 'END' when finished):");
            while (true) {
                line = scanner.nextLine();
                if (line.equals("END")) {
                    break;
                }
                email.addAttachment(line);
            }
        }

        // Analyze the email
        int phishingScore = detector.analyzeEmail(email);

        // Generate and display the report
        String report = detector.generateReport(email, phishingScore);
        System.out.println("\n" + report);

        scanner.close();
    }
}