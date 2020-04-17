import java.io.*;
import java.security.*;
import java.net.Socket;
import java.util.Arrays;
import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.ServerSocket;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerCP1 {
    private ServerSocket serverSocket;
    private Socket socket;
    private DataInputStream from;
    private DataOutputStream target;
    private BufferedReader reader;
    private PrintWriter writer;
    private Cipher EnCipher;
    private KeyFactory keyFactory;
    private boolean finish = false;

    public static void main(String[] args) {
        int port = 1234;
        ServerCP1 server = new ServerCP1(port);
        if (!server.getVerified()) {
            server.close();
            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        if (!server.verifyClient()) {
            server.close();

            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        System.out.println("[INFO] Wait for files from client");
        while (!server.finish) {
            long start = System.currentTimeMillis();
            server.receiveFile();
            long end = System.currentTimeMillis();
            System.out.println("[INFO] Finished transfer in " + (end - start) / 1000 + " seconds");
        }
    }

    public void receiveFile() {
        try {

        } catch (Exception e) {

        }
    }

    public ServerCP1(int port) {
        try {
            serverSocket = new ServerSocket(port);
            socket = serverSocket.accept();
            from = new DataInputStream(socket.getInputStream());
            target = new DataOutputStream(socket.getOutputStream());
            reader = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            writer = new PrintWriter(socket.getOutputStream(), true);

            PrivateKey privateKey = getPrivateKey();
            EnCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            EnCipher.init(Cipher.ENCRYPT_MODE, privateKey);
//            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            deCipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean verifyClient() {
        try {
            // generate and send nonce to server
            byte[] nonce = new byte[32];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(nonce);
            writer.println(DatatypeConverter.printBase64Binary(nonce));
            writer.flush();
            System.out.println("[SEND] Send nonce to client");

            // receive encrypted nonce from client
            byte[] encryptedNonce = DatatypeConverter.parseBase64Binary(reader.readLine());
            System.out.println("[RECV] Receive encrypted nonce from client");

            // request public key from client
            writer.println(Messages.RequestPublicKey);
            writer.flush();
            System.out.println("[SEND] Send request to get public key from client");

            // receive public key from client
            String publicKeyString = reader.readLine();
            byte[] publicKeyByte = DatatypeConverter.parseBase64Binary(publicKeyString);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyByte);
            PublicKey publicKey = keyFactory.generatePublic(spec);

            // decrypt encoded nonce
            Cipher rsaDeCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaDeCipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedNonce = rsaDeCipher.doFinal(encryptedNonce);
            if (!Arrays.equals(decryptedNonce, nonce)) {
                System.out.println("[FAIL] Client authentication failed");
                System.out.println("DEBUG");
                close();
                return false;
            }

            // success fully verified the client
            writer.println(Messages.success);
            writer.flush();
            System.out.println("[INFO] Verification of client identity success");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean getVerified() {
        System.out.println("[INFO] Waiting to be verified by the client");
        try {
            // wait for Hello message and greeting back
            if (!reader.readLine().equals(Messages.StartMessage)) {
                System.out.println("[FAIL] Failed to get response, close");
                close();
                return false;
            }
            System.out.println("[RECV] Receive greeting from client");

            // greeting back
            writer.println(Messages.StartReply);
            writer.flush();
            System.out.println("[SEND] Send greeting to client");

            // receiving nonce from client
            String nonceString = reader.readLine();
            System.out.println("[RECV] Received nonce from client");
            byte[] nonce = DatatypeConverter.parseBase64Binary(nonceString);

            // send encrypted nonce to client
            byte[] encryptedNonce = EnCipher.doFinal(nonce);
            writer.println(DatatypeConverter.printBase64Binary(encryptedNonce));
            writer.flush();
            System.out.println("[SEND] Send encrypted nonce to client");

            String message = reader.readLine();
            System.out.println("[RECV] " + message);
            if (!Messages.RequestCA.equals(message)) {
                System.out.println("[FAIL] Failed to get response, close");
                close();
                return false;
            }

            // load the CA file
            File caFile = new File("example.crt");
            byte[] cert = new byte[(int) caFile.length()];
            BufferedInputStream certInput = new BufferedInputStream(new FileInputStream(caFile));
            certInput.read(cert, 0, cert.length);
            certInput.close();

            // sending the CA to client
            writer.println(DatatypeConverter.printBase64Binary(cert));
            writer.flush();
            System.out.println("[SEND] Sending the cert to client");

            // wait the client to finish verification
            System.out.println("[INFO] Waiting for client to verify");
            if (!Messages.success.equals(reader.readLine())) {
                System.out.println("[FAIL] Verification Failed");
                close();
                return false;
            }

            // verification success
            System.out.println("[INFO] Verification Success");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private PrivateKey getPrivateKey() {
        try {
            byte[] keyByte = Files.readAllBytes(Paths.get("private_key.der"));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyByte);
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void close() {
        try {
            System.out.println("[INFO] Close the connection");
            serverSocket.close();
            socket.close();
            from.close();
            target.close();
            reader.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

//    private PublicKey getPublicKey(byte[] key) {
//
//        return null;
//    }
}
