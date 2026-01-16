package com.java.java;

import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class AgentGenerator {
    public static void main(String[] args) throws IOException, URISyntaxException {
        ArrayList<AgentRelease> releaseList = new ArrayList<>();

        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Brimstone"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Viper"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Omen"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Cypher"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Sova"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Sage"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Phoenix"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Jett"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Raze"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 3, 1), "Breach"));

        releaseList.add(new AgentRelease(LocalDate.of(2020, 6, 2), "Reyna"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 8, 4), "Killjoy"));
        releaseList.add(new AgentRelease(LocalDate.of(2020, 10, 27), "Skye"));

        releaseList.add(new AgentRelease(LocalDate.of(2021, 1, 12), "Yoru"));
        releaseList.add(new AgentRelease(LocalDate.of(2021, 3, 2), "Astra"));
        releaseList.add(new AgentRelease(LocalDate.of(2021, 6, 22), "KAY/O"));
        releaseList.add(new AgentRelease(LocalDate.of(2021, 11, 16), "Chamber"));

        releaseList.add(new AgentRelease(LocalDate.of(2022, 1, 11), "Neon"));
        releaseList.add(new AgentRelease(LocalDate.of(2022, 4, 27), "Fade"));
        releaseList.add(new AgentRelease(LocalDate.of(2022, 10, 18), "Harbor"));

        releaseList.add(new AgentRelease(LocalDate.of(2023, 3, 7), "Gekko"));
        releaseList.add(new AgentRelease(LocalDate.of(2023, 6, 27), "Deadlock"));
        releaseList.add(new AgentRelease(LocalDate.of(2023, 10, 31), "Iso"));

        releaseList.add(new AgentRelease(LocalDate.of(2024, 3, 26), "Clove"));
        releaseList.add(new AgentRelease(LocalDate.of(2024, 8, 27), "Vyse"));

        releaseList.add(new AgentRelease(LocalDate.of(2025, 1, 8), "Tejo"));
        releaseList.add(new AgentRelease(LocalDate.of(2025, 3, 5), "Waylay"));
        releaseList.add(new AgentRelease(LocalDate.of(2025, 10, 7), "Veto"));


        releaseList.add(new AgentRelease(LocalDate.of(99999, 12, 31), "blahaj{1_pref3r_C0unt3r_5tr1ke_tw0}"));

        System.out.println(Arrays.toString(Base64.getEncoder().encode(new GsonBuilder().registerTypeAdapter(LocalDate.class, new LocalDateAdapter()).setPrettyPrinting().create().toJson(releaseList).getBytes())));
        Files.write(Paths.get(AgentRelease.class.getClassLoader().getResource("valorant.jpg").toURI()), Base64.getEncoder().encode(new GsonBuilder().registerTypeAdapter(LocalDate.class, new LocalDateAdapter()).setPrettyPrinting().create().toJson(releaseList).getBytes()), StandardOpenOption.APPEND);
    }
}


