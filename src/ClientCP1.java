import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

public class ClientCP1 {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Cipher EnCipher;
    private KeyPair keyPair;

    public static void main(String[] args) {
        int port = 1234;
        if (args.length > 1) port = Integer.parseInt(args[0]);
        String server = "localhost";
        if (args.length > 2) server = args[1];
        ClientCP1 client = new ClientCP1(server, port);
        if (!client.verifyServer()) {
            client.close();
            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        if (!client.getVerified()) {
            client.close();
            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        System.out.println("[INFO] Start transferring files to server");
        long start = System.currentTimeMillis();
        int i = 2;
        while (i < args.length) {
            String file = args[i];
            boolean success = client.sendFileToServer(file);
            if (!success) {
                System.out.println("[FAIL] Failed to send the file");
            }
            i++;
        }
        long end = System.currentTimeMillis();
        client.writer.println(Messages.SendingFinishAll);
        client.writer.flush();
        System.out.println("[FINISH] Finished transfer in " + (end - start) / 1000 + " seconds");
        client.close();
    }

    public boolean sendFileToServer(String fileName) {
        try {
            File file = new File(fileName);
            if (!file.exists() || file.isDirectory()) {
                System.out.println("[FAIL] File does not exist, please check the filename");
                return true;
            }
            writer.println(fileName);
            writer.flush();
            FileInputStream fileInputStream = new FileInputStream(file);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
            int size = (int) file.length();
            byte[] fileBuffer = new byte[size];
            int nBit = bufferedInputStream.read(fileBuffer, 0, size);
            byte[] encryptedFile = encrypt(fileBuffer);
            writer.println(DatatypeConverter.printBase64Binary(encryptedFile));
            writer.flush();
            bufferedInputStream.close();
            System.out.println("[SEND] Send: " + file + "\tsize: " + nBit);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public byte[] encrypt(byte[] data) {
        int start = 0;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp;
        while (start < data.length) {
            try {
                if (data.length - start >= 117) {
                    temp = EnCipher.doFinal(data, start, 117);
                } else {
                    temp = EnCipher.doFinal(data, start, data.length - start);
                }
                buffer.write(temp, 0, temp.length);
                start += 117;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        byte[] output = buffer.toByteArray();
        try {
            buffer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return output;
    }

    public ClientCP1(String server, int port) {
        try {
            new Thread(() -> keyPair = getKeyPair()).start();
            socket = new Socket(server, port);
            reader = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            writer = new PrintWriter(socket.getOutputStream(), true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean getVerified() {
        try {
            Key publicKey = keyPair.getPublic();
            Key privateKey = keyPair.getPrivate();
            // receive the nonce from server
            String nonce = reader.readLine();
            byte[] serverNonce = DatatypeConverter.parseBase64Binary(nonce);
            System.out.println("[RECV] Received nonce from the server");

            // encrypt nonce and send to server
            Cipher EnCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            EnCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedNonce = EnCipher.doFinal(serverNonce);
            writer.println(DatatypeConverter.printBase64Binary(encryptedNonce));
            writer.flush();
            System.out.println("[SEND] Send encrypted nonce to server");

            // receive request public key from server
            if (!reader.readLine().equals(Messages.RequestPublicKey)) {
                System.out.println("[FAIL] Failed to get response, close");
                close();
                return false;
            }
            System.out.println("[RECV] Receive request for pubic key");

            // send public key to the server
            writer.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            writer.flush();
            System.out.println("[SEND] Send the public key to the server");

            // waiting for server to finish verification
            if (!reader.readLine().equals(Messages.success)) {
                System.out.println("[INFO] Client authentication failed");
                close();
                return false;
            }
            // success fully verified the client
            System.out.println("[INFO] Verification of client identity success");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean verifyServer() {
        System.out.println("[INFO] Start to verify the server");
        try {
            // send Hello to server
            writer.println(Messages.StartMessage);
            writer.flush();
            System.out.println("[SEND] Send greeting to server");

            // receive greeting from server
            if (!reader.readLine().equals(Messages.StartReply)) {
                System.out.println("[FAIL] Failed to get response, close");
                close();
                return false;
            }
            System.out.println("[RECV] Receive greeting from server");

            // send nonce to server make sure no playback
            byte[] nonce = new byte[32];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.nextBytes(nonce);
            String nonceString = DatatypeConverter.printBase64Binary(nonce);
            writer.println(nonceString);
            writer.flush();
            System.out.println("[SEND] Send the nonce to the server");

            // get the encrypted nonce from server
            byte[] encryptedNonce = DatatypeConverter.parseBase64Binary(reader.readLine());
            System.out.println("[RECV] Received encrypted nonce from server");

            // request the cert from server
            writer.println(Messages.RequestCA);
            writer.flush();
            System.out.println("[SEND] Request the server for cert");

            // get the cert from server
            byte[] cert = DatatypeConverter.parseBase64Binary(reader.readLine());
            System.out.println("[RECV] Receive cert from the server");

            // write cert to file and load
            InputStream input = new ByteArrayInputStream(cert);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(input);
            CAcert.checkValidity();
            PublicKey publicKey = CAcert.getPublicKey();
            EnCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            EnCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            System.out.println("[INFO] Extracted public key from cert");

            // use public key to decrypt
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decrypted = cipher.doFinal(encryptedNonce);
            if (!Arrays.equals(decrypted, nonce)) {
                // verification failed
                System.out.println("[FAIL] Verification Failed");
                writer.println(Messages.FailedMessage);
                close();
                return false;
            }
            // verification success
            writer.println(Messages.success);
            writer.flush();
            System.out.println("[INFO] Verification Success");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private KeyPair getKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void close() {
        try {
            System.out.println("[INFO] Close the connection");
            socket.close();
            reader.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
