import java.io.*;
import java.security.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.net.ServerSocket;
import javax.xml.bind.DatatypeConverter;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerCP2 {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Cipher EnCipher;
    private KeyFactory keyFactory;
    private boolean finish = false;
    private Cipher deCipher;
    private final ArrayList<WriteToDisk> writeToDisks = new ArrayList<>();
    SecretKey aesKey;

    public static void main(String[] args) {
        int port = 1234;
        if (args.length > 0)
            port = Integer.parseInt(args[0]);
        System.out.println("[INFO] Listening on port " + port);
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(() -> {
                    ServerCP2 server = new ServerCP2(socket);
                    server.run();
                }).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        if (!getVerified()) {
            close();
            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        if (!verifyClient()) {
            close();
            System.out.println("[FAIL] Verification failed, GOODBYE");
            return;
        }
        System.out.println("[INFO] Wait for files from client");
        while (!finish) {
            long start = System.currentTimeMillis();
            receiveFile();
            long end = System.currentTimeMillis();
            System.out.println("[INFO] Finished transfer in " + (end - start) / 1000 + " seconds");
        }
        System.out.println("[FINISH] Finished transferring all the files");
    }

    public ServerCP2(Socket socket) {
        try {
            this.socket = socket;
            reader = new BufferedReader(new InputStreamReader(new DataInputStream(socket.getInputStream())));
            writer = new PrintWriter(socket.getOutputStream(), true);
            PrivateKey privateKey = getPrivateKey();
            EnCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            EnCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            deCipher.init(Cipher.DECRYPT_MODE, privateKey);
            aesKey = KeyGenerator.getInstance("AES").generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
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
            FileInputStream inputStream = new FileInputStream(caFile);
            BufferedInputStream certInput = new BufferedInputStream(inputStream);
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

            // generate AES key and send to client
            System.out.println("[INFO] Generating AES key");
            byte[] encryptedaesKey = EnCipher.doFinal(aesKey.getEncoded());
            writer.println(DatatypeConverter.printBase64Binary(encryptedaesKey));
            writer.flush();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public void receiveFile() {
        while (!finish && !socket.isClosed()) {
            try {
                String message = reader.readLine();
                if (message.equals(Messages.SendingFinishAll)) {
                    close();
                    for (WriteToDisk w : writeToDisks) {
                        try {
                            w.join();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                    finish = true;
                    return;
                }
                String outputBufferString = reader.readLine();
                WriteToDisk worker = new WriteToDisk(outputBufferString, message);
                writeToDisks.add(worker);
                worker.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public byte[] decrypt(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        int start = 0;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp;
        Cipher aesDecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesDecipher.init(Cipher.DECRYPT_MODE, aesKey);
        while (start < data.length) {
            try {
                synchronized (this) {
                    if (data.length - start >= 128) {
                        temp = aesDecipher.doFinal(data, start, 128);
                    } else {
                        temp = aesDecipher.doFinal(data, start, data.length - start);
                    }
                }
                buffer.write(temp, 0, temp.length);
                start += 128;
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
            socket.close();
            reader.close();
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class WriteToDisk extends Thread {
        String input;
        String name;
        boolean workerFinished = false;

        public WriteToDisk(String input, String name) {
            this.input = input;
            this.name = name;
        }

        @Override
        public void run() {
            try {
                FileOutputStream fileOutputStream = new FileOutputStream("recv_" + name);
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
                byte[] outputBuffer = DatatypeConverter.parseBase64Binary(input);
                byte[] decryptedOutput = decrypt(outputBuffer);
                bufferedOutputStream.write(decryptedOutput, 0, decryptedOutput.length);
                bufferedOutputStream.close();
                fileOutputStream.close();
                System.out.println("[RECV] Received file: " + name + " \tsize: " + decryptedOutput.length);
                workerFinished = true;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
