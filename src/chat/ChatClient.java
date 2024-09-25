package src.chat;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PublicKey;

import encryption.Encryption;

public class ChatClient {
    private JTextArea richTextBox;
    private JTextField textBox;
    private boolean connected;
    private static final String SERVER_PUBLIC_KEY = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGk9wUQ4G9PChyL5SUkCyuHjTNOglEy5h4KEi0xpgjxi/UbIH27NXLXOr94JP1N5pa1BbaVSxlvpuCDF0jF9jlZw5IbBg1OW2R1zUACK+NrUIAYHWtagG7KB/YcyNXHOZ6Icv2lXXd7MbIao3ShrUVXo3u+5BJFCEibd8a/JD/KpAgMBAAE=";
    private PublicKey serverPublicKey;
    private Socket socket;
    private DataOutputStream toServer;
    private DataInputStream fromServer;
    private Key communicationKey;

    public ChatClient() {
        createInterface();
        this.connected = false;
        try {
            serverPublicKey = Encryption.readPublicKey(SERVER_PUBLIC_KEY);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("error on getting server public key: " + e.getMessage());
        }
    }

    private void createInterface() {
        JFrame frame = new JFrame("Chat Client");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                quit();
            }

        });

        // ---------------------- File ---------------------- //
        JMenuBar menuStrip = new JMenuBar();
        JMenu menu = new JMenu("File");
        JMenuItem item1 = new JMenuItem("Connect");
        item1.addActionListener(e -> this.createLoginWindow(null));

        JMenuItem item2 = new JMenuItem("Exit");
        item2.addActionListener(e -> quit());

        menu.add(item1);
        menu.add(item2);

        // ---------------------- Emoji ---------------------- //
        JMenu emojiMenu = new JMenu("Emoji");
        // for smile
        JMenuItem smile = new JMenuItem("😊 smile");
        smile.addActionListener(e -> textBox.setText(textBox.getText() + "😊"));
        emojiMenu.add(smile);
        // for thumbs up
        JMenuItem thumbsup = new JMenuItem("👍 thumbs up");
        thumbsup.addActionListener(e -> textBox.setText(textBox.getText() + "👍"));
        emojiMenu.add(thumbsup);
        // for laughing
        JMenuItem laughing = new JMenuItem("🤣 laughing");
        laughing.addActionListener(e -> textBox.setText(textBox.getText() + "🤣"));
        emojiMenu.add(laughing);
        // for crying
        JMenuItem crying = new JMenuItem("😭 crying");
        crying.addActionListener(e -> textBox.setText(textBox.getText() + "😭"));
        emojiMenu.add(crying);
        // for heart
        JMenuItem heart = new JMenuItem("❤️ heart");
        heart.addActionListener(e -> textBox.setText(textBox.getText() + "❤️"));
        emojiMenu.add(heart);
        // for sparkles
        JMenuItem sparkles = new JMenuItem("✨ sparkles");
        sparkles.addActionListener(e -> textBox.setText(textBox.getText() + "✨"));
        emojiMenu.add(sparkles);
        // for folded hands
        JMenuItem foldedHands = new JMenuItem("🙏 folded hands");
        foldedHands.addActionListener(e -> textBox.setText(textBox.getText() + "🙏"));
        emojiMenu.add(foldedHands);
        menuStrip.add(menu);
        menuStrip.add(emojiMenu);

        // ---------------------- Textboxes ---------------------- //
        richTextBox = new JTextArea();
        richTextBox.setEditable(false);
        richTextBox.setBackground(new Color(240, 240, 240));
        richTextBox.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 20));
        // hide the caret
        richTextBox.setCaretColor(richTextBox.getBackground());
        frame.add(richTextBox, BorderLayout.CENTER);

        textBox = new JTextField();
        textBox.addActionListener(e -> this.send());
        textBox.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 20));
        textBox.setBackground(new Color(255, 255, 255));
        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(e -> this.send());

        JPanel lowerPanel = new JPanel(new FlowLayout());
        lowerPanel.add(textBox, BorderLayout.WEST);
        lowerPanel.add(sendButton, BorderLayout.EAST);
        textBox.setPreferredSize(new Dimension(300, 25));
        sendButton.setPreferredSize(new Dimension(75, 25));
        frame.add(lowerPanel, BorderLayout.SOUTH);
        frame.setJMenuBar(menuStrip);
        frame.setSize(400, 300);
        frame.setVisible(true);
    }

    private void connect(String username, String password, int opcode) {
        /*
         * Connection process:
         * Client: | Server:
         * SEND length of client's encrypted seed | RECEIVE length of client's encrypted
         * seed
         * SEND client's encrypted seed | RECEIVE client's encrypted seed
         * RECEIVE if initial connection has been set | SEND if initial connection has
         * been set
         * SEND encrpyted username | RECEIVE encrypted username
         * SEND encrypted hashed password | RECEIVE encrypted hashed password
         * SEND user's operation (login or signup) | RECEIVE user's operation (login or
         * signup)
         * RECEIVE if user's operation is valid | SEND if user's operation is valid
         */
        try {
            // initial connection setup if not connected
            if (!connected) {
                int port = 9898;
                InetAddress addr = InetAddress.getLocalHost();
                socket = new Socket(addr, port);
                toServer = new DataOutputStream(socket.getOutputStream());
                fromServer = new DataInputStream(socket.getInputStream());
                // set up the connection to server first
                // first, generate AES seed
                byte[] aesSeed = Encryption.generateSeed();
                // encrypt the seed
                byte[] encryptedSeed = Encryption.pkEncrypt(serverPublicKey, aesSeed);
                // send the encrypted AES seed to server
                toServer.writeInt(encryptedSeed.length);
                toServer.write(encryptedSeed);
                System.out.println(aesSeed);
                // generate AES key
                communicationKey = Encryption.generateAESKey(aesSeed);
            }
            // receive from the server about whether the initial connection has been set
            boolean connection_set = fromServer.readBoolean();
            if (connection_set) {
                richTextBox.append("Successfully connected to Server!\n");
            } else {
                richTextBox.append("Failed to connect to Server!\n");
            }

            // send the encrypted username to server
            String encryptedUsername = Encryption.encrypt(communicationKey, username);
            toServer.writeUTF(encryptedUsername);
            toServer.flush();
            // send the hashed & encrpyted password to server
            String hashedPassword = hashToMD5(password, "salt");
            String encryptedPassword = Encryption.encrypt(communicationKey, hashedPassword);
            toServer.writeUTF(encryptedPassword);
            toServer.flush();

            // telling the server if the client is signing up (opcode=0) or logging in
            // (opcode=1)
            toServer.writeInt(opcode);

            // get the result of the validation of the username/password
            int valid = fromServer.readInt();

            // if not valid, ask the user to enter the username/password again
            if (valid==-1&&opcode==1) {
                richTextBox.append("Failed due to invalid Username/Password!\n");
                createLoginWindow("Invalid Username/Password!");
            } else if (valid==1) {
                // tell the user login successfully
                richTextBox.append("Login Successfully!\n");
                // set the connection status to true as the username/password is valid
                connected = true;
                // after connected to server, create a Thread to listen the messages from server
                System.out.println("started a Listener thread");
                Listener listener = new Listener();
                Thread listenThread = new Thread(listener);
                listenThread.start();
            }
            // if creating new account with existed username
            else if (valid==-1&&opcode==0) {
                richTextBox.append("Failed to create a new user!\n");
                createLoginWindow("Username already exists!");
            }
            else if (valid==0) {
                richTextBox.append("Failed since the user is already logging in\n");
                createLoginWindow("User already logging in!");
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("error on setting up connection to server: " + e.getMessage());
        }

    }

    private void createLoginWindow(String info) {
        JFrame loginFrame = new JFrame("Login");
        // --------------- Username --------------- //
        JPanel usernamePanel = new JPanel();
        JLabel usernameLabel = new JLabel("Username: ");
        JTextField usernameText = new JTextField(13);
        usernamePanel.add(usernameLabel, BorderLayout.WEST);
        usernamePanel.add(usernameText, BorderLayout.EAST);

        // --------------- Password ---------------//
        JPanel passwordPanel = new JPanel();
        JLabel passwordLabel = new JLabel(" Password: ");
        JPasswordField passwordText = new JPasswordField(13);
        passwordPanel.add(passwordLabel, BorderLayout.WEST);
        passwordPanel.add(passwordText, BorderLayout.EAST);

        // --------------- Information & Login Button --------------- //
        JPanel lowerPanel = new JPanel(new GridLayout(2, 1));
        JLabel infoLabel = new JLabel(info, JLabel.CENTER);
        JButton signupButton = new JButton("Sign up");
        signupButton.addActionListener(e -> {
            this.connect(usernameText.getText(), new String(passwordText.getPassword()), 0);
            loginFrame.dispose();
        });
        JButton loginButton = new JButton("Log in");
        loginButton.addActionListener(e -> {
            this.connect(usernameText.getText(), new String(passwordText.getPassword()), 1);
            loginFrame.dispose();
        });
        JPanel buttonPanel = new JPanel(new GridLayout(1, 2));
        buttonPanel.add(signupButton);
        buttonPanel.add(loginButton);
        lowerPanel.add(infoLabel, BorderLayout.NORTH);
        lowerPanel.add(buttonPanel, BorderLayout.SOUTH);

        loginFrame.add(usernamePanel, BorderLayout.NORTH);
        loginFrame.add(passwordPanel, BorderLayout.CENTER);
        loginFrame.add(lowerPanel, BorderLayout.SOUTH);
        loginFrame.pack();
        loginFrame.setVisible(true);
        loginFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }

    public String hashToMD5(String input, String salt) {
        StringBuilder result = new StringBuilder();
        try {
            // create an digest instance for MD5
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update((input + salt).getBytes());
            byte[] hash = md5.digest();
            for (int i = 0; i < hash.length; i++) {
                result.append(String.format("%02X", hash[i] & 0xFF));
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("error on hashing: " + e.getMessage());
        }
        return result.toString();

    }

    private void send() {
        if (connected) {
            String content = textBox.getText();
            textBox.setText(null);
            try {
                System.out.println("Start to trying sending message: " + content);
                // encrypt the message
                String encrypted = Encryption.encrypt(communicationKey, content);
                System.out.println("encrypted: " + encrypted);
                toServer.writeUTF(encrypted);
                System.out.println("Written to server");
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("error on sending message: " + e.getMessage());
            }

        }
        // if not connected, tell the user to connect to server first before sending
        // message
        else {
            richTextBox.append("It is not connected to server yet!\n");
            return;
        }

    }

    private void quit() {
        try {
            if (connected) {
                // Telling the server
                System.out.println("trying to QUIT");
                toServer.writeUTF(Encryption.encrypt(communicationKey, "QUIT"));
                Thread.currentThread().interrupt();
                System.out.println("Quit!");
                fromServer.close();
                toServer.close();
                socket.close();
            }
            System.exit(0);
        } catch (Exception ex) {
            // ex.printStackTrace();
            // System.err.println("error on QUIT: " + ex.getMessage());
        }
    }

    private class Listener implements Runnable {
        private boolean listen = true;

        @Override
        public void run() {
            while (listen) {
                try {
                    // if there are any available contents from server to be read
                    if (fromServer.available() > 1) {
                        String encrypted = fromServer.readUTF();
                        System.out.println("communication Key: " + communicationKey);
                        System.out.println("encrypted message: " + encrypted);
                        String decrypted = Encryption.decrypt(communicationKey, encrypted);
                        // close the socket if the server quits
                        if (decrypted.equals("QUIT")) {
                            toServer.close();
                            fromServer.close();
                            socket.close();
                            richTextBox.append("Server QUIT" + "\n");
                            listen = false;
                            // not connected anymore since the server QUIT
                            connected=false;
                        }
                        // in normal cases, append the decrypted message from server to the rich textbox
                        else {
                            richTextBox.append(decrypted + "\n");
                        }
                    }
                    // wait for a while to see if there are anything coming later from server
                    else {
                        Thread.sleep(100);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("error on listening: " + e.getMessage());
                }
            }
        }
    }

    public static void main(String[] args) {
        new ChatClient();
    }
}