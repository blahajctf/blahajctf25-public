package com.java.java;

import com.calendarfx.model.Calendar;
import com.calendarfx.model.Entry;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import javafx.scene.image.Image;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class AgentReleases {
    private final static byte[] data;

    static {
        try {
            data = AgentReleases.class.getClassLoader().getResourceAsStream("valorant.jpg").readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Calendar retrieveCalendar() {
        // Create a Gson instance
        Gson gson = new GsonBuilder().registerTypeAdapter(LocalDate.class, new LocalDateAdapter()).create();
        String raw_json = new String(data, StandardCharsets.UTF_8);
        raw_json = raw_json.substring(raw_json.indexOf("Wwog"));
        raw_json = new String(Base64.getDecoder().decode(raw_json));
        Type listType = new TypeToken<List<AgentRelease>>() {}.getType();
        List<AgentRelease> dates = gson.fromJson(raw_json, listType);

        Calendar calendar = new Calendar("Releases");
        for (AgentRelease dat : dates) {
            Entry entry = new Entry<>(dat.agent);
            entry.setFullDay(true);
            entry.setInterval(dat.release);
            calendar.addEntry(entry);
        }
        return calendar;
    }

    // --- Utility Function (from section 3) ---
    public static Image retrieveImage() {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        return new Image(inputStream);
    }
}

class AgentRelease {
    String agent;
    LocalDate release;

    public AgentRelease(LocalDate rel, String ag) {
        this.agent = ag;
        this.release = rel;
    }
}
