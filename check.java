import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

public class check {
    Base64.Decoder decoder = Base64.getDecoder();

    public check(String regFilePath, String monitor_path, String log_file_path, String hash_type, String publicKeyCertPath) throws Exception {

        BufferedReader input = new BufferedReader(new FileReader(regFilePath));
        logFile.create(log_file_path); // Create log file or append if created earlier
        File[] filesinPath;
        File file = new File(monitor_path);
        filesinPath = file.listFiles();
        boolean checked = false; // Flag for checking the changes (if any) in monitored path

        /* Obtaining public key from certificate */
        FileInputStream fin = new FileInputStream(publicKeyCertPath);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
        PublicKey pk = certificate.getPublicKey();

        /* Getting the registry file content and the signature which is last line of the registry file */
        String last = "", line;
        StringBuilder regFileContent = new StringBuilder();
        while ((line = input.readLine()) != null) {
            regFileContent.append(line);
            last = line;
        }

        regFileContent = new StringBuilder(regFileContent.toString().replace(last, ""));


        /* Getting the hash of the registry file content except the last line which is signature */
        String fileHashOut;
        if (hash_type.equals("MD5")) {
            fileHashOut = Algorithms.getMd5(regFileContent.toString());
        } else {
            fileHashOut = Algorithms.toHexString(Algorithms.getSHA(regFileContent.toString()));
        }

        /* Verifying signature by public key and the hashes of the content of the registry file */
        Signature signature2 = Signature.getInstance("SHA256withRSA");
        signature2.initVerify(pk);
        byte[] messageBytes2 = fileHashOut.getBytes();
        signature2.update(messageBytes2);
        boolean isCorrect = signature2.verify(decoder.decode(last));


        HashMap<String, String> files_and_contents = new HashMap<>(); // Storing the names and contents of the files in a hash map as key-value pairs

        /* Checking if the verification is successful or not */
        if (!isCorrect) {
            logFile.bw.write(logFile.dtf.format(logFile.now) + ": Registry file verification failed!\n"); // Report to the log file
            logFile.bw.close();
            System.exit(0); // Terminate if the verification fails
        }

        /* If verification is successful move on to the checking process of the monitored path's files */
        else {

            /* Read the check.txt which is created by the user as a temporary file and transform the content to a hash map */
            for (String linecheck : Files.readAllLines(Paths.get("check.txt"))) {
                String[] splitted = linecheck.split("\t");
                if (splitted.length != 1) {
                    files_and_contents.put(splitted[0], splitted[1]);
                } else {
                    files_and_contents.put(splitted[0], "");
                }
            }

            /* Check if any file in the monitored path is new or not by looking at the names of the files which are the keyset of the hashmap */
            for (File files : filesinPath) {
                if (!files_and_contents.containsKey(files.getName())) { // If new report to log file
                    checked = true;
                    logFile.bw.write(logFile.dtf.format(logFile.now) + ": " + files.getAbsolutePath() + " is created!\n");
                }
            }

            String path = file.getAbsolutePath(); // Get the monitored file's path to write the inside files' paths correctly when needed

            /* Check if any file in the check.txt is missing or not by looking the files in monitored path */
            for (String s : files_and_contents.keySet()) {

                if (!Arrays.toString(filesinPath).contains(s)) { // If missing report to log file
                    checked = true;
                    logFile.bw.write(logFile.dtf.format(logFile.now) + ": " + path + "/" + s + " is deleted!\n");
                }
                /* If not missing check if the content is changed or not */
                else {
                    StringBuilder file_content = new StringBuilder();
                    /* Read the content of each file to file_content */
                    for (String linecheck : Files.readAllLines(Paths.get(path + "/" + s))) {
                        file_content.append(linecheck);
                    }

                    /* Check if the content is the same with the value (the content of the file) of the key (which is the name of the file) */
                    if (!file_content.toString().equals(files_and_contents.get(s))) { // If not the same report to log file
                        checked = true;
                        logFile.bw.write(logFile.dtf.format(logFile.now) + ": " + path + "/" + s + " is altered!\n");
                    }
                }
            }

            /* Look at the check flag, if stayed false output no change to log file */
            if (!checked) {
                logFile.bw.write(logFile.dtf.format(logFile.now) + ": The directory is checked and no change is detected!\n");
            }

            /* Close the log file */
            logFile.bw.close();
        }
    }
}
