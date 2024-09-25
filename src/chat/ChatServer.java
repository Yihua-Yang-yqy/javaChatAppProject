package src.chat;

import java.awt.BorderLayout;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JTextArea;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.sql.*;

import encryption.Encryption;

public class ChatServer {
    private JTextArea richTextBox;
    private ArrayList<ClientHandler> sessions;
    private Key privateKey;
    private ServerSocket server;
    private Connection connection;

    public ChatServer() {
        createInterface();
        connectToDB();
        sessions = new ArrayList<>();
        richTextBox.append("Server started at " + new Date() + '\n');
        // setup the server
        try {
            privateKey = Encryption.readPrivateKey("./keypairs/pkcs8_key");
            server = new ServerSocket(9898);
            while (true) {
                System.out.println("Accepting new client\n");
                Socket clientSocket = server.accept();
                ClientHandler handler = new ClientHandler(clientSocket);
                Thread thread = new Thread(handler);
                thread.start();
                Thread.sleep(100);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("error on initializing server: " + e.getMessage());
            System.exit(1);
        }
    }

    private void connectToDB() {
        // trying to connect to the database
        try {
            String url = "jdbc:sqlite:database.db";
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(url);
            }
            String createTABLE = "CREATE TABLE IF NOT EXISTS Users (" +
                    "username VARCHAR(32), " +
                    "password VARCHAR(32), " +
                    "PRIMARY KEY(username));";
            Statement statement = connection.createStatement();
            statement.execute(createTABLE);
            statement.close();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private boolean validateUser(String username, String password) {
        boolean valid = false;
        try {
            System.out.println("trying to validate the username/password...");
            System.out.println("Username: " + username);
            System.out.println("Password: " + password);
            if (connection != null) {
                String sql = "SELECT 1 FROM Users WHERE username = ? AND password = ?";
                PreparedStatement statement = connection.prepareStatement(sql);
                statement.setString(1, username);
                statement.setString(2, password);
                ResultSet result = statement.executeQuery();

                valid = result.next();
                System.out.println(valid);
                statement.close();
                result.close();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return valid;
    }

    private boolean createUser(String username, String password) {
        boolean valid = false;
        try {
            if (connection != null) {
                System.out.println("Creating user: " + username);
                // checking if the username already exists in database
                String checkSql = "SELECT COUNT(*) FROM Users WHERE username = ?";
                PreparedStatement check = connection.prepareStatement(checkSql);
                check.setString(1, username);
                ResultSet checkResult = check.executeQuery();
                if (checkResult.next()&&checkResult.getInt(1)>0) {
                    checkResult.close();
                    check.close();
                    // just return false if such username already found in the database
                    return false;
                } else {
                    String sql = "INSERT OR IGNORE INTO Users (username,password) VALUES (?, ?)";
                    PreparedStatement statement = connection.prepareStatement(sql);
                    statement.setString(1, username);
                    statement.setString(2, password);
                    int result = statement.executeUpdate();
                    System.out.println("result: " + result);
                    if (result > 0) {
                        System.out.println("New user added!");
                    }
                    statement.close();
                    return true;
                }

            }
        } catch (Exception e) {
            System.out.println("Error creating user: " + e.getMessage());
        }
        return valid;
    }

    public void createInterface() {
        JFrame frame = new JFrame("Chat Server");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                quit();
            }

        });
        // creating the menu (Connect and Exit)
        JMenuBar menuBar = new JMenuBar();
        JMenu menu = new JMenu("File");

        JMenuItem item2 = new JMenuItem("Exit");
        item2.addActionListener(e -> 
			quit()
		);
        menu.add(item2);
        
        menuBar.add(menu);
        frame.add(menuBar, BorderLayout.NORTH);

        // creating rich textbox to display the chat messages
        // JPanel textPanel=new JPanel();
        richTextBox = new JTextArea();
        richTextBox.setEditable(false);
        frame.add(richTextBox, BorderLayout.CENTER);

        frame.setSize(450, 380);
        frame.setVisible(true);
    }

    private void quit(){
        try {
            // Telling the clients
            System.out.println("trying to QUIT");
            for (ClientHandler clientHandler : sessions) {
                clientHandler.exit();
                Thread.currentThread().interrupt();
                connection.close();
            }
            System.exit(0);

        } catch (Exception ex) {
            ex.printStackTrace();
            System.err.println("error on closing server window: " + ex.getMessage());
            System.exit(1);
        }
    }

    public String hashToMD5(String input) {
        StringBuilder result = new StringBuilder();
        try {
            // create an digest instance for MD5
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(input.getBytes());
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

    private class ClientHandler implements Runnable {
        private Socket client;
        private static int ClientID = 1;
        private int id;
        private Key aesKey;
        private DataInputStream fromClient;
        private DataOutputStream toClient;
        private boolean connected;
        private boolean running = true;
        private String username;

        public ClientHandler(Socket socket) {
            this.client = socket;
            id = ClientID++;
            connected = false;
            richTextBox.append("Starting thread for client " + id + "\n");
            run();
        }

        @Override
        public void run() {
            if (connected) {
                while (running) {
                    try {
                        System.out.println("Handling incoming message...");
                        String encrypted = fromClient.readUTF();
                        System.out.println("read the encrypted message: " + encrypted + "\n");
                        // decrypt the incoming message
                        System.out.println("aesKey: " + aesKey);
                        String decrypted = Encryption.decrypt(aesKey, encrypted);
                        richTextBox.append("From User " + this.username + ": " + decrypted + "\n");
                        System.out.println(sessions.size());

                        // informing all clients in the session
                        for (ClientHandler handler : sessions) {
                            System.out.println("encrypted: " + encrypted + " for User " + handler.username);
                            // if the client is leaving
                            if (decrypted.equals("QUIT")) {
                                // telling others that the client is leaving
                                for (ClientHandler clientHandler : sessions) {
                                    System.out.println("Current ID: " + clientHandler.id);
                                    if (clientHandler.id != this.id) {
                                        System.out.println("send the QUIT to Client" + handler.id);
                                        clientHandler.toClient.writeUTF(Encryption.encrypt(clientHandler.aesKey,
                                                "User " + this.username + " QUIT"));
                                    }
                                }
                                // close sockets
                                fromClient.close();
                                toClient.close();
                                client.close();
                                sessions.remove(this);
                                running = false;
                                System.out.println("Client " + this.id + " is closed " + running);
                            }
                            // for normal cases
                            else {
                                // if the server forward the message to the sender client
                                if (handler.id == this.id) {
                                    encrypted = Encryption.encrypt(this.aesKey, "self." + decrypted);
                                    richTextBox.append("Sending to sender client: " + "self." + decrypted + "\n");
                                    this.toClient.writeUTF(encrypted);
                                }
                                // if the server forward the message to other clients (not sender)
                                else {
                                    encrypted = Encryption.encrypt(handler.aesKey,
                                            "User " + this.username + ": " + decrypted);
                                    richTextBox.append(
                                            "sending to other clients: " + "User " + this.username + ":" + decrypted
                                                    + "\n");
                                    handler.toClient.writeUTF(encrypted);
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.err.println("error on handling incoming message: " + e.getMessage());
                    }
                }
            }

            // if the connection between the client and the server is not setup yet
            else {
                try {
                    fromClient = new DataInputStream(client.getInputStream());
                    toClient = new DataOutputStream(client.getOutputStream());

                    // RECEIVE length of client's encrypted seed
                    int len = fromClient.readInt();
                    // RECEIVE client's encrypted seed
                    if (len > 0) {
                        byte[] encryptedSeed = new byte[len];
                        fromClient.readFully(encryptedSeed, 0, len);
                        System.out.println(encryptedSeed);
                        byte[] decryptedSeed = Encryption.pkDecrypt(privateKey, encryptedSeed);
                        System.out.println("decrypted seed: " + decryptedSeed);
                        // generate the AES key using decrypted seed
                        aesKey = Encryption.generateAESKey(decryptedSeed);
                    }

                    // SEND if initial connection has been set
                    boolean connection_set = true;
                    toClient.writeBoolean(connection_set);

                    int valid = -1;
                    // RECEIVE encrypted username
                    String encryptedUsername = fromClient.readUTF();
                    String decryptedUsername = Encryption.decrypt(aesKey, encryptedUsername);
                    username = decryptedUsername;
                    System.out.println(username);
                    // hash the username for the later database operation
                    String hashedUsername = hashToMD5(decryptedUsername);
                    System.out.println(hashedUsername);

                    // RECEIVE encrypted hashed password
                    String encryptedPassword = fromClient.readUTF();
                    String decryptedPassword = Encryption.decrypt(aesKey, encryptedPassword);
                    System.out.println(decryptedPassword);

                    // RECEIVE user's operation (login or signup)
                    int op = fromClient.readInt();
                    System.out.println("opcode: " + op);
                    boolean valid_bool=false;
                    // if the client is signup, create such account with the username and password
                    if (op == 0) {
                        // create such account in the database
                        // if the username already exists, valid=false
                        valid_bool=createUser(hashedUsername, decryptedPassword);
                    }
                    // if the client is logging in, check if the username/password is valid
                    else {
                        // checking in the database to determine the valid bit based on the database
                        // result
                        valid_bool = validateUser(hashedUsername, decryptedPassword);
                        System.out.println("Validation result: " + valid);
                    }

                    // check if the username is already logging in
                    for (ClientHandler handler : sessions) {
                        if (handler.username.equals(username)) {
                            // telling the client the user is already logging in
                            valid=0;
                        }
                    }

                    if (valid_bool&&valid!=0) {
                        // only when the user pass the validation, we consider the connection is set
                        connected = true;
                        valid=1;
                        sessions.add(this);
                    }
                    else if (!valid_bool&&valid!=0) {
                        valid=-1;
                    } 
                    // SEND if user's operation is valid
                    toClient.writeInt(valid);

                } catch (Exception e) {
                    e.printStackTrace();
                    System.err.println("error on setting up connection: " + e.getMessage());
                }
            }
        }

        public void exit() {
            try {
                toClient.writeUTF(Encryption.encrypt(aesKey, "QUIT"));
                fromClient.close();
                toClient.close();
                client.close();

            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("error on exiting: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        new ChatServer();
    }

}
