package com.waldotaylor.phishingdetector.util;

import com.waldotaylor.phishingdetector.main.PhishingDetector;
import com.waldotaylor.phishingdetector.model.Email;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.Arrays;

public class PhishingEmailResults {
    @FXML
    public void handleCalculateButton(ActionEvent event) throws IOException {
        root = FXMLLoader.load(getClass().getResource("PhishingEmailDetectorResults.fxml"));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
        //resultPage.setText(report);
    }

    public void EmailCreator() {
        String sender = emailTextField.getText();
        String subject = subjectTextField.getText();
        String body = bodyTextField.getText();
        String attachments = attachmentsTextField.getText();

        Email email = new Email(sender, subject, body);
        email.addAttachment(Arrays.toString(attachments.split(",")));

        int score = PhishingDetector.analyzeEmail(email);
        score = PhishingDetector.applyRiskMultipliers(email, score);
        String report = PhishingDetector.generateReport(email, score);
    }
}
}
