### Phishing Email Detector

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/077fbba69f4a480b4434c4ee5a933aeac7d5daf4/UTF-8Screenshot(110).png)

### Introduction
The Phishing Email Detector is a tool that helps you identify potentially malicious emails by analyzing sender information, subject lines, content, links, and attachments. Our application provides both a command-line interface and a graphical user interface for easy analysis of suspicious emails.

**Requirements**
Java Runtime Environment (JRE) 23 or newer
JavaFX (included in installation)

### Installation

Download the latest release from the project repository
Extract the ZIP file to your preferred location
No additional installation is required

Tutorial
Starting the Application

Double-click the application JAR file or run: java com.waldotaylor.phishingdetector.main.PhishingDetectorApplication
You'll see the welcome screen:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/077fbba69f4a480b4434c4ee5a933aeac7d5daf4/UTF-8Screenshot(110).png)

Click the "Press to Start" button to proceed to the main interface.

### Analyzing an Email

In the main interface, enter the email details:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/UTF-8Screenshot(111).png?raw=true)

  - Email Address: Enter the sender's email address
  - Subject: Enter the email subject line
  - Email Body: Paste the content of the email
  - Attachments (optional): Enter filenames separated by commas


Click the "Calculate" button to analyze the email.
Review the results in the panel on the right:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/UTF-8Screenshot(112).png?raw=true)

### Example Analysis
Here's an example of analyzing a phishing email that claims to be from LinkedIn:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/Scam.png?raw=true)

When analyzed with our tool, the report correctly identifies this as highly suspicious:


 
