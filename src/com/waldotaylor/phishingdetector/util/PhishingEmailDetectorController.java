/**
 *
 * @author Taylor Waldo, James Bostick, Bennett Marsee, Caitlyn Pillsbury, Caleb Walton
 * Date: 4/23/2025
 * Section: CSC-331-002
 * Purpose: Handles user interactions from the input form, processes the email content,
 * and displays a phishing analysis report.
 */
package com.waldotaylor.phishingdetector.util;

import com.waldotaylor.phishingdetector.analysis.ThreatDetector;
import com.waldotaylor.phishingdetector.main.PhishingDetector;
import com.waldotaylor.phishingdetector.model.Email;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;
import javafx.scene.Node;
import javafx.scene.control.TextField;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Controller class for the Phishing Email Detector user interface.
 *
 * Handles user interactions from the input form, processes the email content,
 * and displays a phishing analysis report.
 */
public class PhishingEmailDetectorController {
    private Stage stage;
    private Scene scene;
    private Parent root;

    @FXML
    private TextField emailTextField; // TextField extends javafx.scene.control.TextInputControl

    @FXML
    private TextField subjectTextField;

    @FXML
    private TextField bodyTextField;

    @FXML
    private TextField attachmentsTextField;

    @FXML
    private TextArea resultPage;

    private static final Map<ThreatDetector, Double> analyzers = new HashMap<>();

    /**
     * Starts a new screen from the start button action
     *
     * Loads the main application interface from the "PhishingEmailDetector.fxml" file.
     *
     * @param event The ActionEvent triggered by clicking the start button
     * @throws IOException If the FXML file fails to load.
     */
    @FXML //Polymorphism through JavaFX runtime
    public void handleStartButton(ActionEvent event) throws IOException {
        root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("PhishingEmailDetector.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    /**
     * Gathers email data from the text areas, creates an Email object, and analyzes it
     * using the PhishingDetector
     *
     * @return A detailed phishing report generated from the analyzed email
     */
    public String EmailCreator() {
        String sender = emailTextField.getText();
        String subject = subjectTextField.getText();
        String body = bodyTextField.getText();
        String attachments = attachmentsTextField.getText();

        Email email = new Email(sender, subject, body);
        String[] attachArray = attachments.split(",");
        for (String i : attachArray) {
            email.addAttachment(i);
        }

        PhishingDetector detector = new PhishingDetector();
        int score = detector.analyzeEmail(email);
        return detector.generateReport(email, score);
    }

    /**
     * Handles the event when the "Calculate" button is clicked.
     *
     * Calls the EmailCreator method and sets the phishing analysis result into
     * the result box
     *
     * @param event The ActionEvent triggered by clicking the calculate button
     * @throws IOException If an error occurs during report generation or display
     */
    @FXML
    public void handleCalculateButton(ActionEvent event) throws IOException {
        String report = EmailCreator();
        resultPage.setText(report);
    }
}
