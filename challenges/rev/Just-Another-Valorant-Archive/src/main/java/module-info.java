module com.example.java {
    requires javafx.controls;
    requires javafx.fxml;
    requires com.calendarfx.view;
    requires com.google.gson;

    opens com.java.java to javafx.fxml, com.google.gson;
//    opens java.time to com.google.gson;
    exports com.java.java;
}