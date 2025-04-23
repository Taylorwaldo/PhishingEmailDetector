package com.waldotaylor.phishingdetector.util;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * The main application class for the Phishing Email Detector
 *
 * This class launches the JavaFX application and loads the GUI
 * defined in the "PhishingEmailDetectorHome.fxml" file
 */
public class PhishingEmailDetector extends Application {

    /**
     * The entry point for the JavaFX application.
     *
     * @param stage The primary stage for this application
     * @throws Exception If the FXML file cannot be loaded.
     */
    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("PhishingEmailDetectorHome.fxml"));

        Scene scene = new Scene(root);
        stage.setTitle("Phishing Email Detector");
        stage.setScene(scene);
        stage.show();
    }
}
