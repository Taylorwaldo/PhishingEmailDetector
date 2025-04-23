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

public class PhishingEmailDetectorController {
    private Stage stage;
    private Scene scene;
    private Parent root;

    @FXML
    private TextField emailTextField;
    @FXML
    private TextField subjectTextField;
    @FXML
    private TextField bodyTextField;
    @FXML
    private TextField attachmentsTextField;
    @FXML
    private TextArea resultPage;



    @FXML
    public void handleStartButton(ActionEvent event) throws IOException {
        root = FXMLLoader.load(Objects.requireNonNull(getClass().getResource("PhishingEmailDetector.fxml")));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
    private static final Map<ThreatDetector, Double> analyzers = new HashMap<>();

    public String EmailCreator() {

        String sender = emailTextField.getText();
        String subject = subjectTextField.getText();
        String body = bodyTextField.getText();
        String attachments = attachmentsTextField.getText();

        Email email = new Email(sender, subject, body);
        String[] attachArray = attachments.split(",");
        for(String i : attachArray){
            email.addAttachment(i);
        }


        PhishingDetector detector = new PhishingDetector();

        int score = detector.analyzeEmail(email);
        return detector.generateReport(email, score);
    }

    @FXML
    public void handleCalculateButton(ActionEvent event) throws IOException {
        String report = EmailCreator();
        resultPage.setText(report);
    }
}
