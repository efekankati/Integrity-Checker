import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class logFile {
    public static FileWriter fileWriter;
    public static BufferedWriter bw;
    public static DateTimeFormatter dtf;
    public static LocalDateTime now;

    /**
     * This function creates the log file into the given path and writes things needed to be written by using Buffered writer
     *
     * @param logFilePath
     * @throws IOException
     */
    public static void create(String logFilePath) throws IOException {
        File f1 = new File(logFilePath);
        fileWriter = new FileWriter(f1.getName(), true);
        bw = new BufferedWriter(fileWriter);
        dtf = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        now = LocalDateTime.now();
    }
}
