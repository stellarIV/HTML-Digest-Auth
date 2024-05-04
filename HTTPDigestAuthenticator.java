import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class HTTPDigestAuthenticator {
    private static final Map<String, String> users = new HashMap<>();
    private static final Map<String, String> nonces = new HashMap<>();

    public static void main(String[] args) {
        // Add some sample users with passwords
        users.put("Biruk", "Bir123");
        users.put("Arsema", "Ars123");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("1. Authenticate");
            System.out.println("2. Exit");
            System.out.print("Choose an option: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1:
                    System.out.print("Enter username: ");
                    String username = scanner.nextLine();
                    System.out.print("Enter password: ");
                    String password = scanner.nextLine();
                    if (authenticate(username, password)) {
                        System.out.println("Authentication successful!");
                    } else {
                        System.out.println("Authentication failed.");
                    }
                    break;
                case 2:
                    System.out.println("Exiting...");
                    System.exit(0);
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    private static boolean authenticate(String username, String password) {
        // Check if the user exists and the password is correct
        if (users.containsKey(username) && users.get(username).equals(password)) {
            // Generate a nonce
            String nonce = generateNonce();
            nonces.put(username, nonce);
            // Send the nonce to the client
            System.out.println("Nonce: " + nonce);
            // Compute the response hash
            String responseHash = computeResponseHash(username, password, nonce);
            // Simulate sending the response hash to the server for verification
            System.out.println("Response Hash: " + responseHash);
            return true;
        }
        return false;
    }

    private static String generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonceBytes = new byte[16];
        random.nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

    private static String computeResponseHash(String username, String password, String nonce) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            String hashInput = username + ":" + "Digest:" + password + ":" + nonce;
            byte[] hashedBytes = md.digest(hashInput.getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}


class HashedPasswordTuple {
    private final String hashedPassword;
    private final int salt;

    public HashedPasswordTuple(String hashedPassword, int salt) {
        this.hashedPassword = hashedPassword;
        this.salt = salt;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public int getSalt() {
        return salt;
    }
}
