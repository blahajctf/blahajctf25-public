package com.java.java;

import java.time.LocalDate;
import java.time.LocalTime;

import com.calendarfx.model.Calendar;
import com.calendarfx.model.Calendar.Style;
import com.calendarfx.model.CalendarSource;
import com.calendarfx.view.CalendarView;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.image.ImageView;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import static com.java.java.AgentReleases.retrieveImage;

public class ValorantAgentCalendarApp extends Application {


    @Override
    public void start(Stage primaryStage) throws Exception {

        CalendarView calendarView = new CalendarView(); // (1)

        Calendar agentReleases = AgentReleases.retrieveCalendar();

        agentReleases.setStyle(Style.STYLE1); // (3)

        CalendarSource myCalendarSource = new CalendarSource("My Calendars"); // (4)
        myCalendarSource.getCalendars().add(agentReleases);

        calendarView.getCalendarSources().addAll(myCalendarSource); // (5)

        calendarView.setShowAddCalendarButton(false);
        calendarView.setShowPrintButton(false);
        calendarView.setShowPageToolBarControls(false);
//        calendarView.setShow(false);

        // Setting the scene
        calendarView.showYearPage();

        Thread updateTimeThread = new Thread("Calendar: Update Time Thread") {
            @Override
            public void run() {
                while (true) {
                    Platform.runLater(() -> {
                        calendarView.setToday(LocalDate.now());
                        calendarView.setTime(LocalTime.now());
                    });

                    try {
                        // update every 10 seconds
                        sleep(10000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                }
            }
        };

        updateTimeThread.setPriority(Thread.MIN_PRIORITY);
        updateTimeThread.setDaemon(true);
        updateTimeThread.start();
        calendarView.setMinWidth(600);

        ImageView imageView = new ImageView();
        imageView.setImage(retrieveImage());
        imageView.setPreserveRatio(true);
        imageView.setFitHeight(200);

        VBox root = new VBox(imageView, calendarView);
        root.setAlignment(Pos.CENTER);

        Scene scene = new Scene(root);
        primaryStage.setTitle("Just Another Valorant Archive");
        primaryStage.setScene(scene);
        primaryStage.setWidth(1000);
        primaryStage.setHeight(800);
        primaryStage.centerOnScreen();
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}