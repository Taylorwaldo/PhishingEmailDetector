package com.waldotaylor.phishingdetector.util;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.Node;
import javafx.scene.control.TextField;
import java.io.IOException;

public class PhishingEmailDetectorController {
    private Stage stage;
    private Scene scene;
    private Parent root;
    @FXML private TextField emailTextField;
    @FXML private TextField subjectTextField;
    @FXML private TextField bodyTextField;
    @FXML private TextField attachmentsTextField;

    @FXML
    public void handleStartButton(ActionEvent event) throws IOException {
        root = FXMLLoader.load(getClass().getResource("PhishingEmailDetector.fxml"));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    @FXML
    public void handleCalculateButton (ActionEvent event) throws IOException {
        String email = emailTextField.getText();
        String subject = subjectTextField.getText();
        String body = bodyTextField.getText();
        String attachments = attachmentsTextField.getText();





        root = FXMLLoader.load(getClass().getResource("PhishingEmailDetectorCalculated.fxml"));
        stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
        }
    }
