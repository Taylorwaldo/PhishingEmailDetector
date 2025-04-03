### The Phishing Email Detector  

**Phishing** is a form of social engineering and a scam where attackers deceive people into revealing sensitive information or installing malware such as viruses, worms, adware, or ransomware.

**Parsing an email** means breaking down the raw email text into structured components such as:

- Headers (From, To, Subject, Date)
- Body content
- Attachments
- Links
- HTML elements

As a student with a cybersecurity concentration and a victim of social engineering, this project would not only be a graded assignment, but something that would also be touching upon my interests (and potential grudges.) This application would be designed to analyze emails and identify potential phishing attempts through pattern recognition. It would work by parsing an email, either from a file or direct input, and scan/examine it components for suspicious indicators such as misleading links, urgent language, grammatical errors, and requests for sensitive information. Then it’ll calculate a **risk score** to determine the likelihood that the email is a phishing attempt.

### The Classes: Cyber Terminology

**PhishingDetector:** The **main orchestration class** ( “main” indicates its central role in the application's functionality, not that it contains the main() method.) that coordinates the analysis workflow and calculates the final phishing probability score.

**EmailParser:** Breaks down raw email content into components (headers, body, links, etc.) that can be analyzed individually.

**HeaderAnalyzer**: Examines email’s header/subject line.

**BodyAnalyzer**: Processes the main content of the email (text, links, etc)

**Threat Detector (Abstract parent class);**

- **LinkAnalyzer:** Evaluates URLs in the email
- **SenderAnalyzer** (Depending on difficultly would like feedback): Checks the authenticity of the sender's email address and domain for signs of spoofing.
- **ContentAnalyzer:** Scans text content for phishing indicators such as urgent language, requests for personal information, or grammatical errors.
- **AttachmentAnalyzer:** Identifies potentially dangerous file attachments by examining their types and names.

**ReportGenerator:** Compiles analysis results into a comprehensive report detailing the risk assessment and suspicious elements.

### The Driver

**PhishingDetectorDriver:** The main application entry point that handles user input (email submission), calls the PhishingDetector to perform analysis, and displays the results to the user.

### FAQ

**Q: “What’s the difference between Content and body analyzer?”**

**BodyAnalyzer -** about structure and extraction

- Focus on parsing and extracting the raw body content from the email.
- Identifies and extracts different parts like pain text, MTML, links and images
- Prepares it for analysis, does NOT analyze for threats

**ContentAnalyzer** - about threat detection:

- Analyzes the text content
- Looks for urgent language, grammar errors, or request of any info that may be personal.

**Q: “When running the driver file and having the code prompt in the terminal, how can I send the email that I believe is a phishing email?”**

“Enter sender email address: “;

“Enter email subject: “;

“Enter email body: “;

“ Type “END” on new line when finished : “;

Email header input is ideal; collects structured data directly from the user. Prompts for…

- Sender’s email
- Subject
- Body content

Simple yet provides all essential info for the analysis system to give the most accurate grade. Will probably do it out of 100 or 1/10. I haven’t come up for a grading scale yet.

The EmailParser would then process this pre-structured data, HeaderAnalyzer examining the sender and subject for suspicious patterns, while BodyAnalyzer would extract links and analyze text content from the body. Then the results would be sent to the ThreatDetector system. 
The ThreatDetector coordinates its specialized analyzers (LinkAnalyzer, SenderAnalyzer, ContentAnalyzer, and AttachmentAnalyzer) to examine different aspects of the email.

The LinkAnalyzer would work with links extracted by the BodyAnalyzer, the SenderAnalyzer would use information from the HeaderAnalyzer, and the ContentAnalyzer would analyze the text extracted by the BodyAnalyzer.

(No, links and attachments are not the same, they are different elements in an email.)

LinkAnalyzer:

<http://example.com>

The LinkAnalyzer looks for suspicious characteristics such as misleading URLs, shortened links that hide their destination, or domains that mimic legitimate websites with slight misspellings.

AttachmentAnalyzer:

(This is a work in progress mentally, still thinking about the scope of this.)

Identifying attachment filenames and extensions from the email input (which could be as simple as asking "Does this email have attachments? If yes, list their filenames" in your console interface)

Checking extensions against a predefined list of suspicious file types:

**Example**

**SUSPICIOUS_EXTENSIONS = { ".exe", ".bat", ".js", ".vbs", ".scr", ".cmd", ".com"**

**};**


**Q: How would ReportGenerator work? If done out of 0-100 percent? (100 being the highest meaning the email is most likely a phishing attempt.) How, in words would that take the info from the other classes and make a grade?**

The ReportGenerator could work by collecting risk scores from each analyzer (LinkAnalyzer, SenderAnalyzer, ContentAnalyzer, and AttachmentAnalyzer), with each providing a score from 0-100 based on their specific findings. It then applies different weights to these scores based on their reliability as phishing indicators - for example, giving more weight to sender domain spoofing than to urgent language patterns. These weighted scores are mathematically combined (typically through a weighted average) to calculate a final percentage representing the overall likelihood that the email is a phishing attempt. The generator then creates a human-readable report showing both this final percentage and the specific suspicious elements identified by each analyzer, such as misleading links or requests for sensitive information. This approach allows the system to consider multiple factors while prioritizing the most reliable indicators of phishing attacks.

### Hierarchy tree

