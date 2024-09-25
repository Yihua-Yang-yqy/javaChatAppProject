# Java Chat App Project
Final Project of Spring 2024 CS9053
## Project Proposal: Improved Chat Application

**Yihua Yang | yy5028**

### Objective:

The aim of this project is to develop an Improved Local Network Chat Application that facilitates secure and efficient text-based communication among clients within the same network. The application leverages advanced features such as GUI, databases, socket programming, and multithreading to enhance real-time interactions.

### Overview:

The Improved Chat Application builds on the foundational elements of "Assignment 9: Chat Application". It reuses some portions of the existing code, including server-client connection setups, GUI frameworks, AES encryption protocols, and multithreading for message handling. Enhancements in this version include:

- **Emoji Integration:** A new menu on the client side to insert emojis into conversations.
- **User Authentication:** Mandatory login and signup functionality for client-side users when connecting to the server.
- **Enhanced Security:** Implementation of MD5 hashing with salting for securing usernames and passwords.
- **GUI Enhancements:** Introduction of a new GUI window for login/signup processes on the client side.
- **Modified Connection Setup:** A modified connection setup process between clients and server due to the implementation of user authentication.

### Advanced Elements:

- **Graphical User Interface (GUI):** The application will use Java Swing-based GUI to provide a user-friendly interface for clients’ communication. The client interface features a menu bar for login/signup options, server connection, application exit, and emoji insertion. It also includes a non-editable text field for incoming messages, an editable text field for composing messages, and a send button. The server interface displays real-time chat logs.

- **Network:** Communication between clients and the server will be established via socket programming, ensuring efficient data exchange.

- **Database/JDBC:** For storage of usernames and the corresponding passwords, the application will employ a database management system. The use of prepared statements and proper methods will ensure that the application is secure against SQL injection attacks.

- **Multithreading:** Each client connection may be handled by a separate thread, allowing simultaneous processing and responsive user interaction.

- **Security:** All data transmissions are encrypted using AES to maintain confidentiality and integrity. Additionally, all sensitive data is hashed before being stored in the database to enhance security.

