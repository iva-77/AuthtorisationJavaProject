import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.spec.*;

class PartyA {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public PartyA(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    // Получает H(r), B, Enc(PubA, r||B)
    public String respond(String hashR, String bIdentity, byte[] encryptedRB) throws Exception {
        byte[] decrypted = decryptRSA(encryptedRB);
        String[] parts = new String(decrypted, StandardCharsets.UTF_8).split("\\|");

        String r = parts[0];
        String bReceived = parts[1];

        if (!bReceived.equals(bIdentity)) throw new SecurityException("Identity mismatch.");
        if (!hash(r).equals(hashR)) throw new SecurityException("Hash mismatch.");

        return r;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private byte[] decryptRSA(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static String hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(data.getBytes(StandardCharsets.UTF_8)));
    }
}

class PartyB {
    private String identity = "PartyB";
    private SecureRandom random = new SecureRandom();
    private PublicKey pubKeyA;
    private String r;

    public PartyB(PublicKey pubKeyA) {
        this.pubKeyA = pubKeyA;
    }

    public Message sendChallenge() throws Exception {
        r = Integer.toString(random.nextInt(1000000)); // В реальности лучше использовать byte[]
        String hashR = PartyA.hash(r);
        String payload = r + "|" + identity;
        byte[] encrypted = encryptRSA(payload.getBytes(StandardCharsets.UTF_8));
        return new Message(hashR, identity, encrypted);
    }

    public boolean verifyResponse(String responseR) {
        return r.equals(responseR);
    }

    private byte[] encryptRSA(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKeyA);
        return cipher.doFinal(data);
    }

    public static class Message {
        public final String hashR;
        public final String identity;
        public final byte[] encryptedPayload;

        public Message(String hashR, String identity, byte[] encryptedPayload) {
            this.hashR = hashR;
            this.identity = identity;
            this.encryptedPayload = encryptedPayload;
        }
    }
}


void main() {
    testCorrectAttempt();
}

public static void testCorrectAttempt() throws Exception {
        // Генерация ключей для стороны A
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPairA = keyGen.generateKeyPair();

        PartyA a = new PartyA(keyPairA);
        PartyB b = new PartyB(a.getPublicKey());

        // B -> A
        PartyB.Message challenge = b.sendChallenge();

        // A -> B
        String response = a.respond(challenge.hashR, challenge.identity, challenge.encryptedPayload);

        // B проверяет
        if (b.verifyResponse(response)) {
            System.out.println("A успешно аутентифицирована.");
        } else {
            System.out.println("Ошибка аутентификации.");
        }
    }

public static void testImpostorAttempt() throws Exception {
    System.out.println("== Тест: Попытка мошенника выдать себя за PartyA ==");

    // Настоящая PartyA
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair realKeyPair = keyGen.generateKeyPair();
    PartyA realA = new PartyA(realKeyPair);

    // PartyB знает только публичный ключ реального A
    PartyB b = new PartyB(realA.getPublicKey());

    // PartyB отправляет challenge
    PartyB.Message challenge = b.sendChallenge();

    // Мошенник пытается ответить
    KeyPair fakeKeyPair = keyGen.generateKeyPair(); // совершенно другой ключ
    PartyA fakeA = new PartyA(fakeKeyPair);         // притворяется PartyA

    try {
        // fakeA не сможет расшифровать challenge, т.к. у него другой приватный ключ
        String response = fakeA.respond(challenge.hashR, challenge.identity, challenge.encryptedPayload);

        // Проверка B — ожидаем, что она не пройдет
        if (b.verifyResponse(response)) {
            System.out.println("❌ Мошенник успешно прошёл проверку! (ОШИБКА!)");
        } else {
            System.out.println("✅ Мошенник не прошёл проверку. Всё работает корректно.");
        }
    } catch (Exception e) {
        System.out.println("✅ Мошенник не смог расшифровать challenge: " + e.getMessage());
    }
}

