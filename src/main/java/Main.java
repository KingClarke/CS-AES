import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    private static SecretKey secretKey;

    public static void main(String[] args) throws Exception {
        Scanner k = new Scanner(System.in);
        boolean running = true;

        // Generate a secret key for AES encryption
        secretKey = generateKey();

        while (running) {
            System.out.println("==== Menu ====");
            System.out.println("1 : Encrypt a File");
            System.out.println("2 : Decrypt a File");
            System.out.println("3 : Quit");
            System.out.print("Enter your choice: ");

            int choice = getValidatedChoice(k);

            switch (choice) {
                case 1 -> encryptFile(k);
                case 2 -> decryptFile(k);
                case 3 -> {
                    System.out.println("Goodbye!");
                    running = false;
                }
                default -> System.out.println("Invalid option. Please choose 1, 2, or 3.");
            }
        }
    }

    private static int getValidatedChoice(Scanner sc) {
        while (!sc.hasNextInt()) {
            System.out.println("Invalid input. Please enter a number.");
            sc.next(); // Clear invalid input
        }
        return sc.nextInt();
    }

    private static void encryptFile(Scanner k) throws Exception {
        System.out.println("=== Encrypt a File ===");
        System.out.print("Enter the filename to encrypt: ");
        String filename = k.next();

        // Generate a random AES key
        SecretKey randomKey = generateKey();
        String data = readFile(filename);
        String encrypted = encrypt(data, randomKey);
        writeToFile(encrypted, "encrypted.txt");
        String encodedKey = Base64.getEncoder().encodeToString(randomKey.getEncoded());
        System.out.println("Encryption complete!");
        System.out.println("Encrypted data has been written to 'encrypted.txt'.");
        System.out.println("The encryption key is: " + encodedKey);
        System.out.println("** Save this key securely! You will need it to decrypt the file. **");
    }


    private static void decryptFile(Scanner k) throws Exception {
        System.out.println("=== Decrypt a File ===");
        System.out.print("Enter the filename to decrypt: ");
        String filename = k.next();
        System.out.print("Enter the decryption key: ");
        String keyInput = k.next();

        // Decode the Base64 encoded key into a SecretKey
        SecretKey key = decodeKey(keyInput);
        String encryptedData = readFile(filename);
        String decryptedData = decrypt(encryptedData, key);
        writeToFile(decryptedData, "decrypted.txt");
        System.out.println("Decryption complete!");
        System.out.println("Decrypted data has been written to 'decrypted.txt'.");
    }

    private static String readFile(String filename) throws IOException {
        File file = new File(filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    private static void writeToFile(String data, String filename) throws IOException {
        File file = new File(filename);
        try (java.io.FileWriter writer = new java.io.FileWriter(file)) {
            writer.write(data);
            System.out.println("Data written to file: " + filename);
        }
    }

    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private static SecretKey decodeKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    private static String encrypt(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

}
