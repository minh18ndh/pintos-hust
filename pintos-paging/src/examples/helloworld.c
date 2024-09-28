#include <stdio.h>

int main(int argc, char *argv[]) {
    // Check if there are at least two arguments (program name and at least one argument)
    if (argc >= 2) {
        // Print the program name
        printf(" - Program name: %s\n", argv[0]);

        // Print all the arguments starting from the second one
        printf(" - Arguments:\n");
        for (int i = 1; i < argc; i++) {
            printf("  + Argument %d: %s\n", i, argv[i]);
        }
    } else {
        // Print an error message if there are not enough arguments
        printf("Error: Insufficient arguments\n");
    }

    return 0;
}
