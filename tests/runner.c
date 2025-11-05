#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#include "utils.h"

int run_test(const char* executable, int* exit_status) {
  pid_t pid = fork();

  // Failure
  if (pid == -1)
    return -2;


  // Child
  if (pid == 0) {
    #ifndef DEBUG
      int fd[2];
      pipe(fd);
      dup2(fd[1], 1);
    #endif

    char* argv[] = {NULL};
    execv(executable, argv);
    perror("execvp failed");
    exit(122);
  }

  // We're the parent process.
  if (waitpid(pid, exit_status, 0) == -1) {
    perror("waitpid failed");
    return -3;
  }
  return 0;
}


int main() {
  int error = chdir("tests/bin");
  if (error) {
    perror("could not chdir to tests/bin");
    return error;
  }

  DIR* dir = opendir(".");
  if (dir == NULL) {
    perror("failed to open cwd:");
    return -1;
  }

  struct dirent* ent;
  printf("\n");
  while ((ent = readdir(dir)) != NULL) {
    char* suffix = strrchr(ent->d_name, '.');
    if (suffix != NULL && strcmp(suffix, ".test") == 0) {
      printf("RUN " ANSI_COLOR_MAGENTA "%s" ANSI_COLOR_RESET "\n", ent->d_name);

      int test_status;
      int run_status = run_test(ent->d_name, &test_status);

      printf(ANSI_COLOR_RESET "  ");

      if (run_status) {
        printf(ANSI_COLOR_RED "FAILED: cannot run test (%d)\n" ANSI_COLOR_RESET, test_status);
        error = run_status;
        continue;
      }
      if (WIFEXITED(test_status)) {
        int exit_code = WEXITSTATUS(test_status);
        if (exit_code == 0) {
          printf(ANSI_COLOR_GREEN "OK\n" ANSI_COLOR_RESET);
        } else {
          printf(ANSI_COLOR_RED "FAILED: test exited with code %d\n" ANSI_COLOR_RESET, exit_code);
          error = exit_code;
        }
      } else if (WIFSIGNALED(test_status)) {
        int sig = WTERMSIG(test_status);
        char* sig_text = strsignal(sig);
        printf(ANSI_COLOR_RED "FAILED: test terminated: ");
        if (sig_text != NULL) {
          printf("%s", sig_text);
        } else {
          printf("signal %d", sig);
        }
        printf("%s\n", ANSI_COLOR_RESET);
        error = -4;
      } else {
        error = -5;
      }
      printf("\n");
    }
  }
  closedir(dir);

  return error;
}
