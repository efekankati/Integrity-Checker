import java.io.File;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;

public class createReg {
    Scanner input = new Scanner(System.in);
    Base64.Encoder encoder = Base64.getEncoder();

    public createReg(String regFilePath, String monitor_path, String logFilePath, String hashType, String privKeyPath) throws Exception {

        File[] files_in_Path; // To store the files in monitored path
        File file = new File(monitor_path);
        PrintStream registeryFile = new PrintStream(regFilePath); // To write to the registry file
        StringBuilder allOfHashes = new StringBuilder(); // To be able to obtain all the data in the registry file
        PrintStream check_names_of_the_file = new PrintStream("check.txt"); // Creating temporary file to save the content of the files in monitored path

        String fileHashOut; // Hashes of the contents of the files
        int file_count = 0; // Counter for the files to output to the log file

        /* Requesting password to check and report it to the log file */
        System.out.print("Enter password: ");
        String password = input.nextLine();

        /* Reading the encoded private key text file to obtain the private key */
        StringBuilder privKeyText = new StringBuilder();
        for (String line : Files.readAllLines(Paths.get(privKeyPath))) {
            privKeyText.append(line);
        }

        /* Creating log file to keep track of the events happened */
        logFile.create(logFilePath);

        /* Obtaining the private key by decrypting the content and removing the meaningful text added by creator */
        String decrypted_text = Algorithms.decrypt(privKeyText.toString(), Algorithms.getMd5(password), logFile.bw);
        decrypted_text = decrypted_text.replace("meaningfultext", "");
        PrivateKey newly_created_priv_key = Algorithms.loadPrivateKey(decrypted_text);

        /* Listing files of the monitored path */
        files_in_Path = file.listFiles();

        /* Writing the creation of the registry file to the log file */
        logFile.bw.write(logFile.dtf.format(logFile.now) + ": Registery file is created at " + regFilePath + "!\n");

        /* This loop checks the files in the path to be monitored and wites the paths to the registry file and hashes
        of the file's content next to the file's path */
        for (File f : files_in_Path) {

            /* Adding each data of a file in the monitored path to eachFileData to process that */
            StringBuilder eachFileData = new StringBuilder();
            for (String line : Files.readAllLines(Paths.get(f.getAbsolutePath()))) {
                eachFileData.append(line);
            }

            /* Check if the given hash algorithm is whether MD5 or SHA256 */
            if (hashType.equals("MD5")) {
                fileHashOut = Algorithms.getMd5(eachFileData.toString());
            } else {
                fileHashOut = Algorithms.toHexString(Algorithms.getSHA(eachFileData.toString()));
            }

            /* Writing to the related files */
            logFile.bw.write(logFile.dtf.format(logFile.now) + ": " + f.getAbsolutePath() + " is added to registry.\n");
            check_names_of_the_file.println(f.getName() + "\t" + eachFileData);
            registeryFile.println(f.getAbsolutePath() + " " + fileHashOut);
            allOfHashes.append(f.getAbsolutePath()).append(" ").append(fileHashOut);

            file_count++; // Increase file_count by 1
        }

        /* Updating the log file */
        logFile.bw.write(logFile.dtf.format(logFile.now) + ": " + file_count + " file(s) are added to the registry and creation is finished!\n");
        logFile.bw.close();


        String allOfHashesAfter;

        /* Getting the hash of all the content of the registry file */
        if (hashType.equals("MD5")) {
            allOfHashesAfter = Algorithms.getMd5(allOfHashes.toString());
        } else {
            allOfHashesAfter = Algorithms.toHexString(Algorithms.getSHA(allOfHashes.toString()));
        }

        /* Signing process of the registry file */
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(newly_created_priv_key);
        byte[] messageBytes = allOfHashesAfter.getBytes();
        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();

        /* Writing signature to the registry file */
        registeryFile.print(encoder.encodeToString(digitalSignature));
    }
}
