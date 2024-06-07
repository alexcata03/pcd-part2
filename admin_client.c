#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/admin_socket"
#define BUFFER_SIZE 256

void display_menu() {
    printf("Menu:\n");
    printf("1. Exit\n");
    printf("2. Block a user\n");
    printf("3. List users\n");
    printf("Enter choice: ");
}

int main() {
    int sockfd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2];
    int choice;

    // Create a UNIX domain socket
    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // Set up the address structure
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Prompt for username and password
    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove newline character
    // Ensure null termination
    username[sizeof(username) - 1] = '\0'; 

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0'; // Remove newline character
    // Ensure null termination
    password[sizeof(password) - 1] = '\0'; 

    // Send login request
    snprintf(buffer, sizeof(buffer), "LOGIN %.100s %.100s", username, password);
    send(sockfd, buffer, strlen(buffer) + 1, 0); // Include null terminator

    // Receive login response from the server
    recv(sockfd, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);

    // Check if login was successful
    if (strcmp(buffer, "Login successful") == 0) {
        // Send check admin command after successful login
        snprintf(buffer, sizeof(buffer), "CHECK_ADMIN");
        send(sockfd, buffer, strlen(buffer) + 1, 0); // Include null terminator

        // Receive response from the server
        recv(sockfd, buffer, sizeof(buffer), 0);

        // Check if an admin is already connected
        if (strcmp(buffer, "ADMIN_CONNECTED") == 0) {
            printf("An admin is already connected. Exiting...\n");
            close(sockfd);
            exit(EXIT_SUCCESS);
        }

        // Display menu
        while (1) {
            display_menu();
            scanf("%d", &choice);
            getchar(); // Consume newline character

            if (choice == 1) {
                printf("Exiting...\n");
                break;
            } else if (choice == 2) {
                // Block a user
                printf("Write username: ");
                fgets(username, sizeof(username), stdin);
                username[strcspn(username, "\n")] = '\0'; // Remove newline character
                // Ensure null termination
                username[sizeof(username) - 1] = '\0'; 

                // Send block user request
                snprintf(buffer, sizeof(buffer), "REMOVE_USER %s", username);
                send(sockfd, buffer, strlen(buffer) + 1, 0); // Include null terminator

                // Receive response from the server
                recv(sockfd, buffer, sizeof(buffer), 0);
                printf("%s\n", buffer);
            } else if (choice == 3) {
                // List users
                snprintf(buffer, sizeof(buffer), "LIST_USERS");
                send(sockfd, buffer, strlen(buffer) + 1, 0); // Include null terminator

                // Receive response from the server
                recv(sockfd, buffer, sizeof(buffer), 0);
                printf("%s\n", buffer);
            } else {
                printf("Invalid choice. Please try again.\n");
            }
        }
    } else {
        printf("Login failed. Exiting...\n");
    }

    close(sockfd);
    return 0;
}
