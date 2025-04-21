package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;

/*
Purpose ->
ThreatDetector is an abstract base class for building different types of "analyzers" that look at emails and assign a threat score from 0 to 100.

Logic ->
1. Defines an abstract method that all child classes must implement
2. Provides a helper method to get a "easy on the eyes" readable name for each detector.
 */
public abstract class ThreatDetector {  // Add the 'abstract' keyword here

    /**
     * Analyzes an email for suspicious content
     * @param email The email to analyze
     * @return A score from 0-100 indicating the threat level ( 0 = safe according to calculator, 100 = definitely phishing)
     */

    // When you see @Override, this is where all the subclasses are inheriting everything from
    public abstract int analyze(Email email);

    /**
     * Return a name for this detector, useed in reporting
     * Default implementation returns the class name without the "Analyzer" suffix
     * @return The name of the detector
     */

    // example, if the class is LinkAnalyzer, the name would be "Link".

    public String getDetectorName() {
        String className = this.getClass().getSimpleName();         // .getSimpleName() -> Gets just the class name without package info.
        if (className.endsWith("Analyzer")) {                       // Defensive check in case subclass name doesn't end with "Analyzer"
            return className.substring(0, className.length() - 8);
        }
        return className;
    }
}