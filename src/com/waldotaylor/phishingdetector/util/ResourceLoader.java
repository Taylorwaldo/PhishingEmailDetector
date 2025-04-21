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

        try {
            // First try with the current path
            InputStream inputStream = ResourceLoader.class.getResourceAsStream(resourcePath);

            // If that fails, try with a modified path
            if (inputStream == null) {
                // Remove the leading slash if present and try with class loader
                if (resourcePath.startsWith("/")) {
                    resourcePath = resourcePath.substring(1);
                }
                inputStream = ResourceLoader.class.getClassLoader().getResourceAsStream(resourcePath);
            }

            // If still null, try one more approach with direct file path
            if (inputStream == null) {
                // Extract the file name from the path
                String fileName = resourcePath;
                if (resourcePath.contains("/")) {
                    fileName = resourcePath.substring(resourcePath.lastIndexOf('/') + 1);
                }
                inputStream = ResourceLoader.class.getClassLoader().getResourceAsStream(fileName);
            }

            // If we still can't find the resource, throw an exception
            if (inputStream == null) {
                throw new IOException("Resource not found: " + resourcePath);
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) { // Skip empty lines and comments
                        result.add(line);
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading resource: " + resourcePath);
            e.printStackTrace();

            // Return an empty list rather than null to prevent NullPointerExceptions
            return new ArrayList<>();
        }

        return result;
    }
}