#include <signal.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    
    // Give time for the shell to set up job control
    
    // Raise SIGTSTP
    kill(getpid(), SIGTSTP);
    
    return 0;
}