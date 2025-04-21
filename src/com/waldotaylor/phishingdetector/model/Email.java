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
     *
     * @param sender
     * @param subject
     * @param body
     */

    public Email(String sender, String subject, String body) {
        this.sender = sender;
        this.subject = subject;
        this.body = body;
        this.links = new ArrayList<>();
        this.attachments = new ArrayList<>();
    }

    // Getters and Setters

    public String getSender() {
        return sender;
    }

    /**
     *
     * @param sender
     */

    public void getSender(String sender) {
        this.sender = sender; // Needs the new value as input
    }

    public String getSubject() {
        return subject;
    }

    /**
     *
     * @param subject
     */

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBody() {
        return body;
    }

    /**
     *
     * @param body
     */

    public void setBody(String body) {
        this.body = body;
    }

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
     *
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




