package com.waldotaylor.phishingdetector.util;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class PhishingEmailDetector extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("PhishingEmailDetectorHome.fxml"));

        Scene scene = new Scene(root);
        stage.setTitle("Phishing Email Detector");
        stage.setScene(scene);
        stage.show();
    }
}