#include "myshell.h"

void startInteractiveShell(void);

int main(int argc, char *argv[]) {
    char current_path[SHELL_MAX_PATH_LEN];
    char shell_env[SHELL_MAX_PATH_LEN * 2];
    char readme_env[SHELL_MAX_PATH_LEN * 2];
    char new_path[SHELL_MAX_PATH_LEN * 2];

    // Initialize environment paths
    if (!getcwd(current_path, sizeof(current_path))) {
        perror("Error getting current directory");
        return EXIT_FAILURE;
    }

    const char *existing_path = getenv("PATH");
    if (existing_path) {
        snprintf(new_path, sizeof(new_path), "%s:%s", existing_path, current_path);
    } else {
        strncpy(new_path, current_path, sizeof(new_path));
    }
    setenv("PATH", new_path, 1);

    snprintf(shell_env, sizeof(shell_env), "SHELL_PATH=%s/myshell", current_path);
    putenv(shell_env);

    snprintf(readme_env, sizeof(readme_env), "README_PATH=%s/readme", current_path);
    putenv(readme_env);

    if (argc > 1) {
        char *batch_args[SHELL_MAX_ARGS];
        batch_args[0] = "myshell";
        for (int i = 1; i < argc && i < SHELL_MAX_ARGS - 1; ++i) {
            batch_args[i] = argv[i];
        }
        batch_args[argc < SHELL_MAX_ARGS ? argc : SHELL_MAX_ARGS - 1] = NULL;

        int statusFlags[5] = {0};
        ShellRedirectInfo inputRedirects[SHELL_MAX_REDIRECT_FILES] = {0};
        ShellRedirectInfo outputRedirects[SHELL_MAX_REDIRECT_FILES] = {0};

        if (executeBatchFile(batch_args, inputRedirects, outputRedirects, statusFlags) != 0) {
            fprintf(stderr, "Error executing batch file\n");
            return EXIT_FAILURE;
        }
    } else {
        handleClearCommand();
        fprintf(stderr, "\nWelcome to MyShell\n");

        int statusFlags[5] = {0};
        runShellLoop(stdin, NULL, statusFlags);
    }

    return EXIT_SUCCESS;
}

void startInteractiveShell(void) {
    int statusFlags[5] = {0};
    runShellLoop(stdin, NULL, statusFlags);
}
