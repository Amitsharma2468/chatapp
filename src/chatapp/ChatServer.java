package chatapp;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class ChatServer {
    private static final int SERVER_PORT = 12345;
    private static final String DB_URL = "jdbc:mysql://127.0.0.1:3306/userdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "";
    private static Map<String, ObjectOutputStream> clients = new HashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(SERVER_PORT)) {
            System.out.println("Server started on port " + SERVER_PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(new ClientHandler(socket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;
        private ObjectInputStream in;
        private ObjectOutputStream out;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                username = (String) in.readObject();
                clients.put(username, out);

                String message;
                while ((message = (String) in.readObject()) != null) {
                    String[] parts = message.split(":", 3);
                    String sender = parts[0];
                    String receiver = parts[1];
                    String msg = parts[2];

                    saveMessageToDatabase(sender, receiver, msg);

                    ObjectOutputStream receiverOut = clients.get(receiver);
                    if (receiverOut != null) {
                        receiverOut.writeObject(sender + ": " + msg);
                        receiverOut.flush();
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            } finally {
                clients.remove(username);
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private void saveMessageToDatabase(String sender, String receiver, String message) {
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
                String query = "INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
                try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                    pstmt.setInt(1, getUserIdByUsername(conn, sender));
                    pstmt.setInt(2, getUserIdByUsername(conn, receiver));
                    pstmt.setString(3, message);
                    pstmt.executeUpdate();
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
    }
}
