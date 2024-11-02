import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;


/**
 * Password Manager using SHA-256 & PBKDF2
 * Originally created for CSDS-344: Computer Security
 * @author tylerpowers
 */
public class PasswordManager {

    private static String createToken(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
            for (byte hash : encodedHash) {
                String hex = Integer.toHexString(0xff & hash);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            System.out.println("Error in token creation");
        }
        return "";
    }

    private static String createSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static SecretKeySpec createKey(String password, String salt) {
        try {
            byte[] decodedSalt = Base64.getDecoder().decode(salt);
            KeySpec spec = new PBEKeySpec(password.toCharArray(), decodedSalt, 600000, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey sharedKey = factory.generateSecret(spec);
            byte[] encoded = sharedKey.getEncoded();
            return new SecretKeySpec(encoded, "AES");
        } catch (Exception e) {
            System.out.println("Error in key creation");
        }
        return null;
    }

    private static String encrypt(String password, SecretKeySpec key, Cipher cipher) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(password.getBytes());
            return new String(Base64.getEncoder().encode(encryptedData));
        } catch (Exception e) {
            System.out.println("Encryption error");
        }
        return null;
    }

    private static String decrypt(String encrypted, SecretKeySpec key, Cipher cipher) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decoded = Base64.getDecoder().decode(encrypted);
            byte[] decryptedData = cipher.doFinal(decoded);
            return new String(decryptedData);
        } catch (Exception e) {
            System.out.println("Decryption error");
        }
        return null;
    }

    private static void add(Scanner in, SecretKeySpec key, Cipher cipher, File file) {
        System.out.print("Enter label for password: ");
        String label = in.nextLine();
        System.out.print("Enter password to store: ");
        String password = in.nextLine();
        System.out.println("\n");
        String encrypted = encrypt(password, key, cipher);
        try {
            FileWriter writer = new FileWriter(file, true);
            writer.write("\n" + label + ":" + encrypted);
            writer.close();
        } catch (Exception e) {
            System.out.println("Error in password addition");
        }
    }

    private static String findPwd(Scanner in, File file) {
        System.out.print("Enter label for password: ");
        String label = in.nextLine();
        String line;
        String pwdLine = "";
        try {
            FileReader fileReader = new FileReader(file);
            Scanner reader = new Scanner(fileReader);
                while (reader.hasNext()) {
                    line = reader.nextLine();
                    if(line.contains(label)){
                        pwdLine = line;
                    }
                }
                reader.close();
            String[] details = pwdLine.split(":");
            return details[1];
        } catch(Exception e){
            System.out.println("Error finding password.");
        }
        return "";
    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        boolean quit = false;
        Scanner in = new Scanner(System.in);
        Cipher cipher = Cipher.getInstance("AES");

        System.out.print("Enter the passcode to access your passwords: ");
        String passcode = in.nextLine();
        String token = createToken(passcode);

        String salt;

        File file = new File("pwdmanager.txt");

        if (!file.exists()) {
            FileWriter writer = new FileWriter(file, true);
            salt = createSalt();
            writer.write(salt + ":" + token);
            writer.close();
        }
        else {
            FileReader fileReader = new FileReader(file);
            Scanner reader = new Scanner(fileReader);
            String[] details = reader.nextLine().split(":");
            reader.close();
            salt = details[0];
            String storedToken = details[1];
            if (!token.equals(storedToken)) {
                System.out.println("Incorrect password. Reporting to FBI.");
                System.exit(0);
            }
            System.out.println("Authenticated");
        }
        SecretKeySpec key = createKey(passcode, salt);
        while (!quit) {
            System.out.println("a: Add Password\nr: Read Password\nq: Quit");
            System.out.print("Enter choice: ");
            String option = in.nextLine();
            if (option.equals("a")) {
                add(in, key, cipher, file);
            }
            else if (option.equals("r")) {
                String encryptedPassword = findPwd(in, file);
                System.out.println("Found: " + decrypt(encryptedPassword, key, cipher));
            }
            else {
                quit = true;
                System.out.println("Quitting");
            }
        }
    }
}
