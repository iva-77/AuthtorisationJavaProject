import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.spec.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

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


static class PartyA {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String identity = "PartyA";
    private PublicKey pubKeyB;

    public PartyA(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public void setPartyBPublicKey(PublicKey pubKeyB) {
        this.pubKeyB = pubKeyB;
    }

    public String respond(String hashR, String bIdentity, byte[] encryptedRB) throws Exception {
        byte[] decrypted = decryptRSA(encryptedRB);
        String[] parts = new String(decrypted, StandardCharsets.UTF_8).split("\\|");

        String r = parts[0];
        String bReceived = parts[1];

        if (!bReceived.equals(bIdentity)) throw new SecurityException("Identity mismatch.");
        if (!hash(r).equals(hashR)) throw new SecurityException("Hash mismatch.");

        return r;
    }

    public Message sendChallengeToB() throws Exception {
        String r = Integer.toString(new SecureRandom().nextInt(1000000));
        String hashR = hash(r);
        String payload = r + "|" + identity;
        byte[] encrypted = encryptRSA(payload.getBytes(StandardCharsets.UTF_8), pubKeyB);
        return new Message(hashR, identity, encrypted);
    }

    public boolean verifyResponseFromB(String response, String expectedR) {
        return response.equals(expectedR);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private byte[] decryptRSA(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private byte[] encryptRSA(byte[] data, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    public static String hash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(digest.digest(data.getBytes(StandardCharsets.UTF_8)));
    }
}

static class PartyB {
    private String identity = "PartyB";
    private SecureRandom random = new SecureRandom();
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey pubKeyA;
    private String r;

    public PartyB(KeyPair keyPair) {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public void setPartyAPublicKey(PublicKey pubKeyA) {
        this.pubKeyA = pubKeyA;
    }

    public Message sendChallengeToA() throws Exception {
        r = Integer.toString(random.nextInt(1000000));
        String hashR = PartyA.hash(r);
        String payload = r + "|" + identity;
        byte[] encrypted = encryptRSA(payload.getBytes(StandardCharsets.UTF_8), pubKeyA);
        return new Message(hashR, identity, encrypted);
    }

    public String respond(String hashR, String aIdentity, byte[] encryptedRA) throws Exception {
        byte[] decrypted = decryptRSA(encryptedRA);
        String[] parts = new String(decrypted, StandardCharsets.UTF_8).split("\\|");

        String r = parts[0];
        String aReceived = parts[1];

        if (!aReceived.equals(aIdentity)) throw new SecurityException("Identity mismatch.");
        if (!PartyA.hash(r).equals(hashR)) throw new SecurityException("Hash mismatch.");

        return r;
    }

    public boolean verifyResponseFromA(String rResponse) {
        return r.equals(rResponse);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private byte[] decryptRSA(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    private byte[] encryptRSA(byte[] data, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }
}


private static void createAndShowGUI() {
    JFrame frame = new JFrame("Тест Аутентификации");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(500, 400);
    frame.setLayout(new BorderLayout());

    // Панель с кнопками
    JPanel buttonPanel = new JPanel();
    JButton testCorrectBtn = new JButton("✅ Тест: Настоящая PartyA");
    JButton testImpostorBtn = new JButton("❌ Тест: Мошенник");

    buttonPanel.add(testCorrectBtn);
    buttonPanel.add(testImpostorBtn);

    // Слайдер (на будущее, например, для размера ключа)
    JSlider keySizeSlider = new JSlider(512, 4096, 2048);
    keySizeSlider.setMajorTickSpacing(1024);
    keySizeSlider.setMinorTickSpacing(256);
    keySizeSlider.setPaintTicks(true);
    keySizeSlider.setPaintLabels(true);
    keySizeSlider.setBorder(BorderFactory.createTitledBorder("Размер ключа RSA"));

    // Лог вывода
    JTextArea logArea = new JTextArea();
    logArea.setEditable(false);
    JScrollPane scrollPane = new JScrollPane(logArea);

    // Обработка нажатий
    testCorrectBtn.addActionListener((ActionEvent e) -> {
        logArea.append("▶ Запуск теста настоящей PartyA...\n");
        try {
            String result = testMutualAuthentication();
            logArea.append(result + "\n\n");
        } catch (Exception ex) {
            logArea.append("Ошибка: " + ex.getMessage() + "\n\n");
        }
    });

    testImpostorBtn.addActionListener((ActionEvent e) -> {
        logArea.append("▶ Запуск теста мошенника...\n");
        try {
            String result = testImpostorAttempt();
            logArea.append(result + "\n\n");
        } catch (Exception ex) {
            logArea.append("Ошибка: " + ex.getMessage() + "\n\n");
        }
    });

    // Добавление компонентов в окно
    frame.add(buttonPanel, BorderLayout.NORTH);
    frame.add(keySizeSlider, BorderLayout.SOUTH);
    frame.add(scrollPane, BorderLayout.CENTER);

    frame.setVisible(true);
}

void main() {
    try {
        SwingUtilities.invokeLater(() -> createAndShowGUI());
    } catch (Exception e)
    {
        System.out.println("Что то критичное.");
    }
}

public static String testMutualAuthentication() throws Exception {
    // Генерация ключей для обеих сторон
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPairA = keyGen.generateKeyPair();
    KeyPair keyPairB = keyGen.generateKeyPair();

    PartyA a = new PartyA(keyPairA);
    PartyB b = new PartyB(keyPairB);

    // Обмен открытыми ключами
    a.setPartyBPublicKey(b.getPublicKey());
    b.setPartyAPublicKey(a.getPublicKey());

    // Шаг 1: B -> A (вызов)
    Message challengeFromB = b.sendChallengeToA();
    String responseFromA = a.respond(challengeFromB.hashR, challengeFromB.identity, challengeFromB.encryptedPayload);
    boolean bVerifiedA = b.verifyResponseFromA(responseFromA);

    // Шаг 2: A -> B (обратный вызов)
    Message challengeFromA = a.sendChallengeToB();
    String responseFromB = b.respond(challengeFromA.hashR, challengeFromA.identity, challengeFromA.encryptedPayload);
    boolean aVerifiedB = a.verifyResponseFromB(responseFromB, challengeFromA.hashR);

    if (bVerifiedA && aVerifiedB) {
        System.out.println("Обе стороны успешно аутентифицированы.");
        return "Обе стороны успешно аутентифицированы.";
    } else {
        System.out.println("Ошибка аутентификации одной из сторон.");
        return "Ошибка аутентификации одной из сторон.";
    }
}

public static String testImpostorAttempt() throws Exception {
    System.out.println("== Тест: Попытка мошенника выдать себя за PartyA ==");

    // Настоящая PartyA
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair realKeyPairA = keyGen.generateKeyPair();
    PartyA realA = new PartyA(realKeyPairA);

    // PartyB знает только публичный ключ настоящей PartyA
    KeyPair keyPairB = keyGen.generateKeyPair();
    PartyB b = new PartyB(keyPairB);
    b.setPartyAPublicKey(realA.getPublicKey());

    // PartyB отправляет challenge
    Message challengeFromB = b.sendChallengeToA();

    // Мошенник создаёт свою пару ключей и притворяется PartyA
    KeyPair fakeKeyPairA = keyGen.generateKeyPair();
    PartyA fakeA = new PartyA(fakeKeyPairA);

    try {
        // Мошенник пытается ответить на challenge от B
        String fakeResponse = fakeA.respond(challengeFromB.hashR, challengeFromB.identity, challengeFromB.encryptedPayload);

        // B проверяет, подставное значение совпадает ли с ожидаемым (нет)
        if (b.verifyResponseFromA(fakeResponse)) {
            System.out.println("❌ Мошенник успешно прошёл проверку! (ОШИБКА!)");
            return "❌ Мошенник успешно прошёл проверку! (ОШИБКА!)";
        } else {
            System.out.println("✅ Мошенник не прошёл проверку. Всё работает корректно.");
            return "✅ Мошенник не прошёл проверку. Всё работает корректно.";
        }
    } catch (Exception e) {
        // Ожидается ошибка при расшифровке challenge (у мошенника другой приватный ключ)
        System.out.println("✅ Мошенник не смог расшифровать challenge: " + e.getMessage());
        return "✅ Мошенник не смог расшифровать challenge: " + e.getMessage();
    }
}
