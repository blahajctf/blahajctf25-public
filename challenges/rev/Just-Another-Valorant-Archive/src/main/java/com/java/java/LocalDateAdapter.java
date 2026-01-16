package com.java.java;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

class LocalDateAdapter extends TypeAdapter<LocalDate> {

    // Define the standard ISO 8601 date formatter
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE;

    @Override
    public void write(JsonWriter out, LocalDate value) throws IOException {
        if (value == null) {
            out.nullValue();
        } else {
            // Serialize LocalDate object into a string using the formatter
            out.value(FORMATTER.format(value));
        }
    }

    @Override
    public LocalDate read(JsonReader in) throws IOException {
        // Check for null token to prevent errors
        if (in.peek() == JsonToken.NULL) {
            in.nextNull();
            return null;
        } else {
            // Read the string and parse it back into a LocalDate object
            String dateString = in.nextString();
            return LocalDate.parse(dateString, FORMATTER);
        }
    }
}
