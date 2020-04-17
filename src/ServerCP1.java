import javafx.scene.shape.Path;

import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerCP1 {
    private ServerSocket serverSocket;
    private Socket socket;
    private DataInputStream from;
    private DataOutputStream target;
    private boolean verified = false;
    private boolean closed = true;
    private BufferedReader reader;
    private PrintWriter writer;
    private Cipher EnCipher;
    private Cipher DeCipher;
    private PrivateKey privateKey;
    private final String privateKeyFile = "private_key.der";
    private final String CAfile = "private_key.der";

    public static void main(String[] args) {
        int port = 1234;
        ServerCP1 server = new ServerCP1(port);
        server.getVerified();
    }

    public ServerCP1(int port) {
        try {
            serverSocket = new ServerSocket(port);
            socket = serverSocket.accept();
            from = new DataInputStream(socket.getInputStream());
            target = new DataOutputStream(socket.getOutputStream());
            reader = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            writer = new PrintWriter(socket.getOutputStream(), true);
            privateKey = getPrivateKey();
            EnCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            EnCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            DeCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            DeCipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean getVerified() {
        try {
            // receiving nonce from client
            String nonceString = reader.readLine();
            System.out.println("RECV:" + nonceString);
            byte[] nonce = nonceString.getBytes();
            // send encrypted nonce to client
            byte[] encryptedNonce = EnCipher.doFinal(nonce);
            writer.println(new String(encryptedNonce, "UTF-16"));
            writer.flush();
            System.out.println("SEND:" + new String(encryptedNonce, "UTF-16"));
            String message = reader.readLine();
            System.out.println("RECV:"+message);
            if (!Messages.RequestCA.equals(message)) {
                System.out.println("Failed to get response, close");
                close();
                return false;
            }
            // load the CA file
            File caFile = new File(CAfile);
            byte[] cert = new byte[(int) caFile.length()];
            BufferedInputStream certInput = new BufferedInputStream(new FileInputStream(caFile));
            certInput.read(cert, 0, cert.length);
            certInput.close();
            // sending the CA to client
            writer.println(new String(cert));
            writer.flush();
            System.out.println("Sending the cert to client");
//            System.out.println("Waiting for client to verify");
//            if (!Messages.success.equals(reader.readLine())) {
//                System.out.println("Verification Failed");
//                close();
//                return false;
//            }
//            System.out.println("Verification Success");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private PrivateKey getPrivateKey() {
        try {
            byte[] keyByte = Files.readAllBytes(Paths.get(privateKeyFile));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyByte);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void close() {
        try {
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
}


