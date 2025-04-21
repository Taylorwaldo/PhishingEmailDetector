package com.waldotaylor.phishingdetector.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for loading resources from the classpath
 */
public class ResourceLoader {

    /**
     * Loads a resource file into a List of Strings
     *
     * @param resourcePath The path to the resource
     * @return A List containing each line of the resource file
     */
    public static List<String> loadResourceAsList(String resourcePath) {
        List<String> result = new ArrayList<>();

        try (InputStream inputStream = ResourceLoader.class.getResourceAsStream(resourcePath);
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) { // Skip empty lines and comments
                    result.add(line);
                }
            }
        } catch (IOException | NullPointerException e) {
            System.err.println("Error loading resource: " + resourcePath);
            e.printStackTrace();
        }

        return result;
    }
}
