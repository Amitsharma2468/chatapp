package chatapp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class UserAuthApp {
    private static final String DB_URL = "jdbc:mysql://127.0.0.1:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "";
    private static int loggedInUserId = -1;
    private static String loggedInUsername = "";
    private static final String SERVER_ADDRESS = "127.0.0.1";
    private static final int SERVER_PORT = 12345;
    private Socket socket;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private JTextArea chatArea;
    private JTextField messageField;

    public static void main(String[] args) {
        // Load the MySQL JDBC driver
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return;
        }

        EventQueue.invokeLater(() -> {
            try {
                new UserAuthApp().showLoginPage();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void showLoginPage() {
        JFrame frame = new JFrame("Login");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(300, 200);

        JPanel panel = new JPanel();
        frame.getContentPane().add(panel, BorderLayout.CENTER);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JTextField usernameField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        JButton loginButton = new JButton("Log In");
        JButton signupButton = new JButton("Sign Up");

        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);
        panel.add(loginButton);
        panel.add(signupButton);

        loginButton.addActionListener(e -> logIn(frame, usernameField.getText(), new String(passwordField.getPassword())));
        signupButton.addActionListener(e -> {
            frame.dispose();
            showSignupPage();
        });

        frame.setVisible(true);
    }

    private void showSignupPage() {
        JFrame frame = new JFrame("Sign Up");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        JPanel panel = new JPanel();
        frame.getContentPane().add(panel, BorderLayout.CENTER);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JTextField usernameField = new JTextField();
        JTextField emailField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        JButton signupButton = new JButton("Sign Up");
        JButton backButton = new JButton("Back to Login");

        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Email:"));
        panel.add(emailField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);
        panel.add(signupButton);
        panel.add(backButton);

        signupButton.addActionListener(e -> signUp(frame, usernameField.getText(), emailField.getText(), new String(passwordField.getPassword())));
        backButton.addActionListener(e -> {
            frame.dispose();
            showLoginPage();
        });

        frame.setVisible(true);
    }

    private void signUp(JFrame frame, String username, String email, String password) {
        if (username.isEmpty() || email.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "All fields must be filled", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, username);
                pstmt.setString(2, email);
                pstmt.setString(3, hashPassword(password));

                int rowsAffected = pstmt.executeUpdate();
                if (rowsAffected > 0) {
                    JOptionPane.showMessageDialog(frame, "Signup successful!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    frame.dispose();
                    showLoginPage();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Error during signup", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void logIn(JFrame frame, String username, String password) {
        if (username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Username and password must be filled", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM users WHERE username = ? AND password = ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setString(1, username);
                pstmt.setString(2, hashPassword(password));

                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        loggedInUserId = rs.getInt("id");
                        loggedInUsername = rs.getString("username");
                        JOptionPane.showMessageDialog(frame, "Login successful!", "Success", JOptionPane.INFORMATION_MESSAGE);
                        frame.dispose();
                        showProfilePage();
                    } else {
                        JOptionPane.showMessageDialog(frame, "Invalid username or password", "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Error during login", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showProfilePage() {
        JFrame frame = new JFrame("Profile");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 500);

        JPanel panel = new JPanel();
        frame.getContentPane().add(panel, BorderLayout.CENTER);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JLabel usernameLabel = new JLabel("Logged in as: " + loggedInUsername);
        panel.add(usernameLabel);

        List<String> otherUsers = getOtherUsers(loggedInUserId);

        for (String user : otherUsers) {
            JButton userButton = new JButton(user);
            userButton.addActionListener(e -> {
                showChatBox(user);
                loadChatHistory(user);
            });
            panel.add(userButton);
        }

        frame.setVisible(true);
    }

    private List<String> getOtherUsers(int loggedInUserId) {
        List<String> users = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT username FROM users WHERE id != ?";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                pstmt.setInt(1, loggedInUserId);
                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        users.add(rs.getString("username"));
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users;
    }

    private void showChatBox(String user) {
        JFrame frame = new JFrame("Chat with " + user);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(400, 400);

        JPanel panel = new JPanel();
        frame.getContentPane().add(panel, BorderLayout.CENTER);
        panel.setLayout(new BorderLayout());

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane chatScrollPane = new JScrollPane(chatArea);
        panel.add(chatScrollPane, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BorderLayout());

        messageField = new JTextField();
        JButton sendButton = new JButton("Send");

        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);

        panel.add(inputPanel, BorderLayout.SOUTH);

        sendButton.addActionListener(e -> sendMessage(user));
        messageField.addActionListener(e -> sendMessage(user));

        frame.setVisible(true);

        connectToServer();
    }

    private void sendMessage(String receiver) {
        String message = messageField.getText();
        if (!message.isEmpty()) {
            try {
                out.writeObject(loggedInUsername + ":" + receiver + ":" + message);
                out.flush();
                chatArea.append("You: " + message + "\n");
                messageField.setText("");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void connectToServer() {
        try {
            socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            new Thread(() -> {
                try {
                    out.writeObject(loggedInUsername);
                    out.flush();
                    while (true) {
                        Object obj = in.readObject();
                        if (obj instanceof String) {
                            String message = (String) obj;
                            SwingUtilities.invokeLater(() -> chatArea.append(message + "\n"));
                        }
                    }
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }).start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadChatHistory(String user) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String query = "SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp";
            try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                int userId = getUserIdByUsername(conn, user);
                if (userId == -1) return;

                pstmt.setInt(1, loggedInUserId);
                pstmt.setInt(2, userId);
                pstmt.setInt(3, userId);
                pstmt.setInt(4, loggedInUserId);

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        String sender = getUsernameById(conn, rs.getInt("sender_id"));
                        String message = rs.getString("content");
                        chatArea.append(sender + ": " + message + "\n");
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private int getUserIdByUsername(Connection conn, String username) throws SQLException {
        String query = "SELECT id FROM users WHERE username = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id");
                }
            }
        }
        return -1;
    }

    private String getUsernameById(Connection conn, int userId) throws SQLException {
        String query = "SELECT username FROM users WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("username");
                }
            }
        }
        return "";
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
