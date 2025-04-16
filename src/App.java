import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.spec.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;


static class PartyA {
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

static class PartyB {
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
            String result = testCorrectAttempt();
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

    }
}

public static String testCorrectAttempt() throws Exception {
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
            return ("A успешно аутентифицирована.");
        } else {
            System.out.println("Ошибка аутентификации.");
            return ("Ошибка аутентификации.");
        }
    }

public static String testImpostorAttempt() throws Exception {
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
            return ("❌ Мошенник успешно прошёл проверку! (ОШИБКА!)");
        } else {
            System.out.println("✅ Мошенник не прошёл проверку. Всё работает корректно.");
            return ("✅ Мошенник не прошёл проверку. Всё работает корректно.");
        }
    } catch (Exception e) {
        System.out.println("✅ Мошенник не смог расшифровать challenge: " + e.getMessage());
        return ("✅ Мошенник не смог расшифровать challenge: " + e.getMessage());
    }
}

