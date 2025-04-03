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

    /*
    note2self - delete l8r
    - links and attachments aren't parameters in the constructor.
    - they are initialized as empty Arraylists in constructor
    - every new "Email" object starts with an empty collection that can be populated l8r
    - Not every email will have links/attachment, excluding it makes it an optional component
    - Flexibility in adding items
     */

    public Email(String sender, String subject, String body) {
        this.sender = sender;
        this.subject = subject;
        this.body = body;
        this.links = new ArrayList<>();
        this.attachments = new ArrayList<>();
    }

    // Getters and Setters


    /*
    note2self - delete l8r
    public String methods (getters)
        these return a value of type string
        example - getSender() returns the value stored in the sender field
        no param


     public void methods (setters):
        Void - don't return any value
        example: setSender(String sender) just sets the value, doesn't need to return anything
        params because they update/change a field value and need to know what new value to set
     */

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

    // Add a single link (setting via setLinks would replace the entire list of links)
    /*
    The parameter in addLink(String link) is named "link" (singular) because
    we are adding just one link at a time to the collection.
     */

    /**
     *
     * @param link
     */

    public void addLink(String link) {
        this.links.add(link);
    }

    public List<String> getAttachments() {
        return attachments;
    }

    /**
     *
     * @param attachment
     */

    public void addAttachment(String attachment) {
        this.attachments.add(attachment);
    }

    /*
@Override: An annotation that tells the compiler we're overriding
a method from a parent class (toString() from Object).
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




