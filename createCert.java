import java.io.FileInputStream;
import java.io.PrintStream;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class createCert {
    Base64.Encoder encoder = Base64.getEncoder();
    static PrivateKey key;
    static String encryptedString;
    static String password;

    public createCert(String privateKeyPath, String publicKeyCertPath) throws Exception {
        Scanner input = new Scanner(System.in);

        /* Generating command on command prompt to create the keystore file including all the related key and certificate datas */
        String[] command = {"keytool", "-genkeypair", "-alias", "assignment", "-keyalg", "RSA", "-dname", "CN=rajind,OU=dev,O=bft,L=mt,C=Srilanka", "-keystore", "assignment3.jks", "-keypass", "qwerty", "-storepass", "qwerty"};
        Process p1 = Runtime.getRuntime().exec(command);
        p1.waitFor();

        /* Getting password to use it in the encryption process of the private key file creation */
        System.out.print("Enter password: ");
        password = input.nextLine();

        /* Transform .jks file to a keystore class object */
        FileInputStream is = new FileInputStream("./assignment3.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "qwerty".toCharArray());
        String alias = "assignment";

        /* Get private key from .jks file */
        key = (PrivateKey) (keystore.getKey(alias, "qwerty".toCharArray()));

        /* Get certificate of public key by running command on command prompt */
        String[] command2 = {"keytool", "-export", "-alias", "assignment", "-keystore", "assignment3.jks", "-storepass", "qwerty", "-rfc", "-file", publicKeyCertPath};
        Process p2 = Runtime.getRuntime().exec(command2);
        p2.waitFor();
        /* Apply MD5 hashing algorithm to the password to later send to the encryption */
        password = Algorithms.getMd5(password);

        encryptedString = encoder.encodeToString(key.getEncoded()); // Encode the private key
        encryptedString += "meaningfultext"; // Add meaningful text at the end of the private key content

        /* Encrypt the end result with using encrypted data of the private key file and hashed password got from the user */
        encryptedString = Algorithms.encrypt(encryptedString, password);

        /* Output the end result to the private key file with given path as an argument */
        PrintStream privKeyOut = new PrintStream(privateKeyPath);
        privKeyOut.println(encryptedString);
    }
}
