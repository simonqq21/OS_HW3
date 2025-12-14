#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define NUM_PROCESSES 5

int main()
{
    pid_t pid;

    // 1. Creation Loop
    for (int i = 0; i < NUM_PROCESSES; i++)
    {
        pid = fork();

        if (pid < 0)
        {
            // Error handling
            perror("Fork failed");
            exit(1);
        }
        else if (pid == 0)
        {
            // --- CHILD PROCESS CODE ---
            printf("[Child %d] PID: %d, Parent PID: %d\n", i, getpid(), getppid());

            // Simulate work
            sleep(1);

            // CRITICAL: Child must exit here to avoid looping and forking again!
            exit(0);
        }

        // --- PARENT PROCESS CODE ---
        // The parent continues the loop to spawn the next child.
    }

    // 2. Waiting Loop (Parent Only)
    // The parent reaches this point only after the creation loop is finished.
    // It must wait for children to prevent "Zombie" processes.
    for (int i = 0; i < NUM_PROCESSES; i++)
    {
        wait(NULL); // Wait for any child to terminate
    }

    printf("[Parent] All children have finished. Exiting.\n");
    return 0;
}