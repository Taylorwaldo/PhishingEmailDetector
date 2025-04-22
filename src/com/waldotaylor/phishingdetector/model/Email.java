/**
 *
 * @author Taylor Waldo, James Bostick, Bennett Marsee, Caitlyn Pillsbury, Caleb Walton
 * Date: 4/23/2025
 * Section: CSC-331-002
 * Purpose: To define the parts of the email that need to be analyzed and their associated methods. This class
 * serves as the foundation of our application.
 *
 */

package com.waldotaylor.phishingdetector.model;

import java.util.ArrayList;
import java.util.List;

/*
Email class -> foundation of our application
 */

public class Email {
    private String sender;
    private String subject;
    private String body;
    private List<String> links;
    private List<String> attachments;

    /**
     * This is the constructor of an Email object.
     * @param sender The domain and email address of the sender to be analyzed
     * @param subject The subject of the email to be analyzed.
     * @param body The body of the email to be analyzed.
     */

    public Email(String sender, String subject, String body) {
        this.sender = sender;
        this.subject = subject;
        this.body = body;
        this.links = new ArrayList<>();
        this.attachments = new ArrayList<>();
    }

    // Getters and Setters

    /**
     * The getter for the sender variable
     * @return The sender of the email object
     */
    public String getSender() {
        return sender;
    }

    /**
     * The setter for the sender variable
     * @param sender The new sender of the email object
     */

    public void getSender(String sender) {
        this.sender = sender; // Needs the new value as input
    }

    /**
     * The getter for the subject variable
     * @return The subject of the email object
     */
    public String getSubject() {
        return subject;
    }

    /**
     * The setter for the subject variable
     * @param subject The new subject of the email object
     */

    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     * The getter for the body variable
     * @return The body of the email object
     */
    public String getBody() {
        return body;
    }

    /**
     * The setter for the body variable
     * @param body The new body of the object
     */

    public void setBody(String body) {
        this.body = body;
    }

    /**
     * The getter for the links variable
     * @return The links of the email object
     */
    public List<String> getLinks() {
        return links;
    }

    /**
     * Adds a single link to the email
     * @param link The URL to add
     */

    public void addLink(String link) {
        this.links.add(link);
    }

    /**
     * The getter for the attachments variable
     * @return The list of attachments found in the email
     */

    public List<String> getAttachments() {
        return attachments;
    }

    /**
     * Adds a single attachment to the email
     * @param attachment The attachment filename or description
     */

    public void addAttachment(String attachment) {
        this.attachments.add(attachment);
    }

    /*
    Returns a string representation of the Email object
 */

    /**
     *
     * @return A string representation of the email object. Result string includes sender address, name of subject,
     * number of characters in body, number of links, and number of attachments.
     */
    @Override
    public String toString() {
        return "Email{" +
                "sender='" + sender + '\'' +
                ", subject='" + subject + '\'' +
                ", body length=" + (body != null ? body.length() : 0) +
                ", links=" + links.size() +
                ", attachments=" + attachments.size() +
                '}';
        /*
        Example Output - Email{sender='suspicious@example.com', subject='You won!', body length=157, links=3, attachments=1}
        // TEST COMMENT 4/3
         */
    }

}




