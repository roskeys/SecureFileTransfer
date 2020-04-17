import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class ClientCP1 {
    private Socket socket;
    private DataInputStream from;
    private DataOutputStream target;
    private boolean verified = false;
    private boolean closed = true;
    private BufferedReader reader;
    private PrintWriter writer;
    private PublicKey publicKey;
    private final String publicKeyPath = "public_key.der";

    public static void main(String[] args) {
        int port = 1234;
        String server = "localhost";
        ClientCP1 client = new ClientCP1(server, port);
        client.verifyServer();
    }

    public ClientCP1(String server, int port) {
        try {
            socket = new Socket(server, port);
            from = new DataInputStream(socket.getInputStream());
            target = new DataOutputStream(socket.getOutputStream());
            reader = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            writer = new PrintWriter(socket.getOutputStream(), true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean verifyServer() {
        try {
            // send nonce to server make sure no playback
            byte[] nonce = new byte[32];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(nonce);
            String nonceString = new String(nonce);
            writer.println(nonceString);
            writer.flush();
            System.out.println("SEND:" + nonceString);
            // get the encrypted nonce from server
            String encryptedNonceString = reader.readLine();
            System.out.println("Received encrypted nonce from server");
            System.out.println(encryptedNonceString);
            // request the cert from server
            writer.println(Messages.RequestCA);
            writer.flush();
            // get the cert from server
            byte[] cert = reader.readLine().getBytes();
            FileOutputStream output = new FileOutputStream("CA.crt");
            output.write(cert);
            Thread.sleep(1000);
            FileInputStream input = new FileInputStream("CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(input);
//            CAcert.checkValidity();
//            PublicKey publicKey =CAcert.getPublicKey();
//            System.out.println("Extracted public key");
//            // use public key to decrypt
//            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            cipher.init(Cipher.DECRYPT_MODE, publicKey);
//            byte[] decrypted = cipher.doFinal(encryptedNonceString.getBytes());
//            if (!Arrays.equals(decrypted, nonce)){
//                System.out.println("Verification Failed");
//                writer.println(Messages.FailedMessage);
//                close();
//                return false;
//            }
//            System.out.println("Verification Success");
//            writer.println(Messages.success);
            return false;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public void verifyKey(PublicKey key){
//        ServerCert.checkValidity();
    }

    private PublicKey getPublicKey(byte[] cert) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void close() {
        try {
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
