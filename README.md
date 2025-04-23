### Phishing Email Detector

![Image Alt](image_url)

### Introduction
The Phishing Email Detector is a tool that helps you identify potentially malicious emails by analyzing sender information, subject lines, content, links, and attachments. Our application provides both a command-line interface and a graphical user interface for easy analysis of suspicious emails.

**Requirements**
Java Runtime Environment (JRE) 23 or newer
JavaFX (included in installation)

### Installation

Download the latest release from the project repository

Extract the ZIP file to your preferred location

No additional installation is required

### Tutorial
Starting the Application

Double-click the application JAR file or run: java com.waldotaylor.phishingdetector.main.PhishingDetectorApplication

You'll see the welcome screen:

![Image Alt](image_url)

Click the "Press to Start" button to proceed to the main interface.

### Analyzing an Email

In the main interface, enter the email details:

![Image Alt](image_url)

  - Email Address: Enter the sender's email address
  - Subject: Enter the email subject line
  - Email Body: Paste the content of the email
  - Attachments (optional): Enter filenames separated by commas


Click the "Calculate" button to analyze the email.

Review the results in the panel on the right:

![Image Alt](image_url)

### Example Analysis
Here's an example of analyzing a phishing email that claims to be from **LinkedIn**:

![Image Alt](image_url)

When analyzed with our tool, the report correctly identifies this as highly suspicious:

![Image Alt](image_url)



Here's an example of analyzing a phishing email that claims to be from **LinkedIn**:

![Image Alt](image_url)

When analyzed with our tool, the report correctly identifies this as highly suspicious:

![Image Alt](image_url)


Here's an example of analyzing a phishing email that claims to be from **Booking.com**:

![Image Alt](image_url)

When analyzed with our tool, the report correctly identifies this as highly suspicious:

![Image Alt](image_url)



### Phishing Probability Scale
The application uses a 0-100 scoring system to indicate the likelihood of an email being a phishing attempt:

**0-14: SAFE - No significant phishing indicators detected**

**15-39: SOME SUSPICIOUS ELEMENTS - Likely legitimate but proceed with caution**

**40-59: MODERATELY SUSPICIOUS - May be a phishing attempt, verify before taking action**

**60-100: HIGHLY SUSPICIOUS - Likely a phishing attempt, do not click links or download attachments**

### Best Practices
Even with this tool, follow these best practices when dealing with suspicious emails:

Never click links in suspicious emails

Verify sender identities through official channels

Don't open unexpected attachments

Be wary of urgent requests or threats

Check for spelling and grammar errors

Hover over links to view the actual URL

Report phishing attempts to your IT department or service provider


----------------------------------------------------------------------------------------------------------------------
Developed by Taylor Waldo, James Bostick, Bennett Marsee, Caitlyn Pillsbury, and Caleb Walton
Feel free to use, modify, and distribute this software for educational purposes.
 
