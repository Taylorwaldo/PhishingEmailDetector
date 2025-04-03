package com.waldotaylor.phishingdetector.analysis;
import com.waldotaylor.phishingdetector.model.Email;

// Abstract class - created using analyze()
// "extends ThreatDetector"

public class ThreatDetector {
    public abstract int analyze(Email email);
}
