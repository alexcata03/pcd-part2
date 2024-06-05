#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/admin_socket"
#define BUFFER_SIZE 256

void handle_menu(int sockfd);

int main() {
    int sockfd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2];

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(EXIT_FAILURE);
    }

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    snprintf(buffer, sizeof(buffer), "LOGIN %.100s %.100s", username, password);
    send(sockfd, buffer, strlen(buffer), 0);

    memset(buffer, 0, sizeof(buffer));
    recv(sockfd, buffer, sizeof(buffer), 0);
    printf("%s\n", buffer);

    if (strcmp(buffer, "Login successful") == 0) {
        handle_menu(sockfd); // Call menu function
    }

    close(sockfd);
    return 0;
}

void handle_menu(int sockfd) {
    int choice;
    char buffer[BUFFER_SIZE];

    while (1) {
        printf("\nMenu:\n");
        printf("1. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        while (getchar() != '\n'); // Clear input buffer

        switch (choice) {
            case 1:
                printf("Exiting...\n");
                return;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}
