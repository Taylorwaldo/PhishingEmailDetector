### Phishing Email Detector

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/custom_Logo.png?raw=true)

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

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/Homepage.png?raw=true)

Click the "Press to Start" button to proceed to the main interface.

### Analyzing an Email

Locate any email in you inbox that you believe is a phishing attempt. For educational purposes, here is an example that is not so subtle. 

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/LinkedIn_potential_spam.png?raw=true)


In the main interface (pictured below), enter the email details:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/Second_page.png?raw=true)

  - Email Address: Enter the sender's email address
  - Subject: Enter the email subject line
  - Email Body: Paste the content of the email
  - Attachments (optional): Enter filenames separated by commas


Click the "Calculate" button to analyze the email.

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/inputExample_LinkedIn.png?raw=true)

Review the results in the panel on the right:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/LinkedIn_Report.png?raw=true)

### Example Analysis
 

Here's an example, a more subtle example, of analyzing a phishing email that claims to be from **Github**:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/GitHub_potential_spam.png?raw=true)

When analyzed with our tool, the report correctly identifies this as moderately suspicous:

**EDIT:** Time didn't permit to program logic to detect typosquatting or character substitution attacks like:  
"glthub.com" instead of "github.com"

Currently LinkAnalyzer.java is checking for several suspicious patterns in URLs:

Non-HTTPS links

IP addresses in URLs

Known suspicious domains

Unusually long domain names

URLs with many special characters

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/GitHub_report.png?raw=true)


Here's an example of analyzing a phishing email that claims to be from **Booking.com**:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/Bookingdotcom_potential_spam.png?raw=true)

When analyzed with our tool, the report correctly identifies this as highly suspicious:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/bookingcomReport.png?raw=true)

Here's an example of analyzing a phishing email that claims to be from **accounts.google.com**:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/Gmail_Potential.png?raw=true)

When analyzed with our tool, the report correctly identifies that this email does appear to be safe:

![Image Alt](https://github.com/Taylorwaldo/PhishingEmailDetector/blob/main/images/gmail_report.png?raw=true)


### The Phishing Email Detector provides detailed information in its output about what specific suspicious elements it found in an email. Here are examples of what the program might tell users:

**Sender Analysis Warnings**
-----------------------------

"Sender domain does not match display name (score: 40)"

"Sender uses a known suspicious domain (score: 60)"

"Sender domain contains unusual numeric characters (score: 15)"

"Unusually long sender domain detected (score: 10)"

**Subject Line Warnings**
-----------------------------

"Subject line contains urgent language (score: 15)"

"Excessive exclamation marks in subject (score: 15)"

"Subject written entirely in ALL CAPS (score: 20)"

"Subject contains suspicious keywords: 'verify', 'urgent', 'account' (score: 25)"

**Content Analysis Warnings**
-----------------------------

- "Email contains multiple phishing keywords (score: 35)"

- "Generic greeting detected ('Dear Customer') (score: 15)"

- "Requests for sensitive information detected (score: 40)"

- "Excessive use of urgent language (score: 25)"

- "Contains threats of account closure (score: 35)"

- "Multiple sections of ALL CAPS text detected (score: 10)"

**Link Analysis Warnings**
-----------------------------

- "Links use unsecured HTTP protocol instead of HTTPS (score: 25)"

- "Link contains IP address instead of domain name (score: 50)"

- "Suspicious domain detected in link (score: 25)"

- "Link may be mimicking legitimate domain: 'amaz0n.com' vs 'amazon.com' (score: 40)"

- "URL contains excessive special characters (score: 15)"

**Attachment Analysis Warnings**
--------------------------------

- "HIGH RISK: Contains executable file extension (.exe) (score: 80)"

- "MEDIUM RISK: Contains potentially dangerous file type (.pdf) (score: 40)"

- "SUSPICIOUS: Multiple file extensions detected (possible disguised file) (score: 15)"

**Combination Warnings**
-----------------------------

- "CRITICAL: Requests for sensitive information combined with suspicious attachments (40% risk escalation)"

- "CRITICAL: Suspicious links combined with requests for sensitive information (30% risk escalation)"

**Any new findings can be added to its respectful resource txt file**



### Phishing Probability Scale
The application uses a 0-100 scoring system to indicate the likelihood of an email being a phishing attempt:
------------------------------------------------------------------------------

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




Phishing email templates provided by/created using CanIPhish.com's simulation services

----------------------------------------------------------------------------------------------------------------------
Developed by Taylor Waldo, James Bostick, Bennett Marsee, Caitlyn Pillsbury, and Caleb Walton
Feel free to use, modify, and distribute this software for educational purposes.
 
