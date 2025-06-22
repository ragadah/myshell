#include "myshell.h"

static int is_background_batch = 0;      // Flag for background batch process
static char current_batch_file[SHELL_MAX_PATH_LEN] = ""; // Current batch file path (Use SHELL_MAX_PATH_LEN)
static int batch_line_number = 0;        // Line number in batch file
static int is_batch_mode = 0;            // Flag for batch mode execution


int executeCommandLine(char *commandLine) {
    pid_t pid;
    char *args[SHELL_MAX_ARGS] = {NULL};
    int statusFlags[5] = {0};
    ShellRedirectInfo inputRedirects[SHELL_MAX_REDIRECT_FILES] = {0};
    ShellRedirectInfo outputRedirects[SHELL_MAX_REDIRECT_FILES] = {0};

    if (commandLine == NULL || strlen(commandLine) == 0 || strspn(commandLine, " \t\n") == strlen(commandLine)) {
        return 0;
    }
    
    char *cmdLineCopy = strdup(commandLine); 
    if (cmdLineCopy == NULL) {
        reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "strdup failed");
        return -1;
    }

    int error = parseCommandLine(cmdLineCopy, args, statusFlags, inputRedirects, outputRedirects);
    if(error || args[0] == NULL) {
        free(cmdLineCopy);
        return -1;
    }

    if(strcmp(args[0], "quit") == 0 || strcmp(args[0], "exit") == 0) {
        if(args[1]) {
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, args[0]);
            free(cmdLineCopy);
            return -1;
        }

        if(is_batch_mode) {
            fprintf(stderr, "Batch file \"%s\" finished execution\n", current_batch_file);
        } else {
            fprintf(stderr, "\nGoodbye\n\n");
        }
        free(cmdLineCopy);
        exit(0);
    }

    if(statusFlags[0]) {
        switch(pid = fork()) {
            case -1:
                reportShellError(FORK_ERROR, NULL, NULL, NULL, "fork");
                break;
            case 0:
                shellDelay(1);
                executeSingleCommand(args, inputRedirects, outputRedirects, statusFlags);
                free(cmdLineCopy);
                exit(0);
            default:
                if(!is_batch_mode) {
                    fprintf(stderr, "Background process PID: %d\n", pid);
                }
        }
    } else {
        executeSingleCommand(args, inputRedirects, outputRedirects, statusFlags);
    }
    
    free(cmdLineCopy);
    return 0;
}

int executeSingleCommand(char **args, const ShellRedirectInfo *inputRedirects,
                         const ShellRedirectInfo *outputRedirects, int *statusFlags) {
    char fullPath[SHELL_MAX_PATH_LEN];
    pid_t childPid;

    int original_stdout = dup(STDOUT_FILENO);
    int original_stdin = dup(STDIN_FILENO);

    if(statusFlags[2] > 0) {
        const ShellRedirectInfo *lastOutputRedirect = &outputRedirects[statusFlags[2] - 1];
        getFullPath(fullPath, lastOutputRedirect->fileName);
        int fd = open(fullPath, (strcmp(lastOutputRedirect->openMode, "a") == 0) ? O_WRONLY | O_CREAT | O_APPEND : O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, lastOutputRedirect->fileName);
            return -1;
        }
        if (dup2(fd, STDOUT_FILENO) == -1) {
            reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "dup2 for stdout");
            close(fd);
            return -1;
        }
        close(fd);
    }

    if(strcmp(args[0], "cd") == 0) {
        int ret = handleCdCommand(args, inputRedirects, statusFlags);
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return ret;
    }
    else if(strcmp(args[0], "clr") == 0 || strcmp(args[0], "clear") == 0) {
        handleClearCommand();
        if(args[1] || statusFlags[1] || statusFlags[2]) { // If arguments or redirections given for clr/clear
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, args[0]);
            // Still clear screen, but report error
        }
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return 0;
    }
    else if(strcmp(args[0], "dir") == 0) {
        int ret = handleDirCommand(args, inputRedirects, statusFlags);
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return ret;
    }
    else if(strcmp(args[0], "echo") == 0) {
        int ret = handleEchoCommand(args, inputRedirects, statusFlags);
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return ret;
    }
    else if(strcmp(args[0], "environ") == 0) {
        listEnvironmentVariables();
        if(statusFlags[1] > 0) { // Check input redirection for environ
            reportShellError(INVALID_REDIRECTION, NULL, inputRedirects, statusFlags, "environ");
        }
        if(args[1]) { // Check extra arguments for environ
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, "environ");
        }
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return 0;
    }
    else if(strcmp(args[0], "help") == 0 || strcmp(args[0], "?") == 0) {
        int ret = displayHelp(args, outputRedirects, statusFlags);
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return ret;
    }
    else if(strcmp(args[0], "pause") == 0) {
        if(args[1] || statusFlags[1] || statusFlags[2]) {
            reportShellError(INVALID_ARGUMENT, NULL, NULL, NULL, args[0]);
        }
        handlePauseCommand();
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return 0;
    }
    else if(strcmp(args[0], "pwd") == 0) {
        displayCurrentWorkingDirectory();
        if(statusFlags[1] > 0) { // Check input redirection for pwd
            reportShellError(INVALID_REDIRECTION, NULL, inputRedirects, statusFlags, "pwd");
        }
        if(args[1]) { // Check extra arguments for pwd
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, "pwd");
        }
        // Restore stdout/stdin for built-in commands
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return 0;
    }
    else if(strcmp(args[0], "myshell") == 0 || strcmp(args[0], "shell") == 0) {
        // When 'myshell' is called, it handles its own input/output context.
        // We restore original stdout/stdin AFTER this call returns.
        int ret = executeBatchFile(args, inputRedirects, outputRedirects, statusFlags);
        if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
        if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
        close(original_stdout);
        close(original_stdin);
        return ret;
    }

    // Handle external commands
    switch(childPid = fork()) {
        case -1:
            reportShellError(FORK_ERROR, NULL, NULL, NULL, "fork");
            // Restore stdout/stdin on fork error before returning
            if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
            if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
            close(original_stdout);
            close(original_stdin);
            break;
        case 0: // Child process
            if(statusFlags[1] > 0) { // Input redirection (only the last one matters)
                const ShellRedirectInfo *lastInputRedirect = &inputRedirects[statusFlags[1] - 1];
                getFullPath(fullPath, lastInputRedirect->fileName);
                int fd = open(fullPath, O_RDONLY);
                if (fd < 0) {
                    reportShellError(FILE_ERROR, NULL, NULL, NULL, lastInputRedirect->fileName);
                    exit(1); // Child exits on file open error
                }
                if (dup2(fd, STDIN_FILENO) == -1) {
                    reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "dup2 for stdin");
                    close(fd);
                    exit(1);
                }
                close(fd); // Close the original file descriptor
            }
            // Output redirection is already handled if statusFlags[2] > 0

            execvp(args[0], args);
            // If execvp returns, it means an error occurred
            reportShellError(COMMAND_NOT_FOUND, args, NULL, NULL, NULL);
            exit(1); // Child exits on execvp error
        default:
            if(!statusFlags[0]) { // Wait if not background
                waitpid(childPid, NULL, WUNTRACED);
            }
            // Parent process: Restore original stdout/stdin
            if (statusFlags[2] > 0) dup2(original_stdout, STDOUT_FILENO);
            if (statusFlags[1] > 0) dup2(original_stdin, STDIN_FILENO);
            close(original_stdout);
            close(original_stdin);
    }
    
    // Close original FDs in parent (if not already closed by dup2)
    close(original_stdout);
    close(original_stdin);

    return 0;
}

/* Command Parsing Functions */

int parseCommandLine(char *buffer, char **args, int *statusFlags,
                     ShellRedirectInfo *inputRedirects, ShellRedirectInfo *outputRedirects) {
    int argc = 0;
    int inRedirectCount = 0, outRedirectCount = 0;
    char *token = NULL;
    char *saveptr = NULL;
    int parsingError = 0;

    // Initialize structures
    memset(inputRedirects, 0, sizeof(ShellRedirectInfo) * SHELL_MAX_REDIRECT_FILES);
    memset(outputRedirects, 0, sizeof(ShellRedirectInfo) * SHELL_MAX_REDIRECT_FILES);
    memset(statusFlags, 0, 5 * sizeof(int)); // statusFlags array size is 5

    // Tokenize the input buffer
    token = strtok_r(buffer, SHELL_TOKEN_SEPARATORS, &saveptr);
    while(token != NULL) {
        // Check for comment
        if(*token == '#') break; // All text after # is ignored

        // Check for background execution
        if(strcmp(token, "&") == 0) {
            statusFlags[0] = 1; // Background flag set
            token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
            continue; // Continue parsing, in case there are arguments after & (though uncommon)
        }

        // Check for input redirection
        if(strcmp(token, "<") == 0) {
            if(inRedirectCount >= SHELL_MAX_REDIRECT_FILES) {
                reportShellError(TOO_MANY_REDIRECTIONS, NULL, NULL, NULL, "input");
                parsingError = 1;
                break;
            }
            token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
            if(!token) { // Missing filename after '<'
                reportShellError(INVALID_REDIRECTION, NULL, NULL, NULL, "< (missing filename)");
                parsingError = 1;
                break;
            }
            // Only the LAST input redirect counts, so we just overwrite previous ones
            inputRedirects[0].fileName = token; // Assuming only one input redirect for simplicity for now
            strcpy(inputRedirects[0].openMode, "r");
            strcpy(inputRedirects[0].operator, "<");
            inRedirectCount = 1; // Mark that an input redirect was found
            statusFlags[1] = 1; // Set input redirect flag
            token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
            continue;
        }

        // Check for output redirection
        if(strcmp(token, ">") == 0 || strcmp(token, ">>") == 0) {
            if(outRedirectCount >= SHELL_MAX_REDIRECT_FILES) {
                reportShellError(TOO_MANY_REDIRECTIONS, NULL, NULL, NULL, "output");
                parsingError = 1;
                break;
            }
            // Store the operator before advancing token
            char current_operator[3];
            strcpy(current_operator, token);

            token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
            if(!token) { // Missing filename after '>' or '>>'
                reportShellError(INVALID_REDIRECTION, NULL, NULL, NULL, ">, >> (missing filename)");
                parsingError = 1;
                break;
            }
            // Only the LAST output redirect counts
            outputRedirects[0].fileName = token; // Assuming only one output redirect for simplicity for now
            strcpy(outputRedirects[0].operator, current_operator);
            strcpy(outputRedirects[0].openMode, (strcmp(current_operator, ">>") == 0) ? "a" : "w");
            outRedirectCount = 1; // Mark that an output redirect was found
            statusFlags[2] = 1; // Set output redirect flag
            token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
            continue;
        }

        // Regular argument
        if(argc >= SHELL_MAX_ARGS - 1) {
            reportShellError(TOO_MANY_ARGUMENTS, NULL, NULL, NULL, NULL);
            parsingError = 1;
            break;
        }
        args[argc++] = token;
        token = strtok_r(NULL, SHELL_TOKEN_SEPARATORS, &saveptr);
    }

    args[argc] = NULL; // NULL terminate the argument list
    // statusFlags[1] and statusFlags[2] are already set to 1 if redirects were found, 0 otherwise.
    // They indicate if ANY redirection was present.
    // The actual count of redirections is now handled by inRedirectCount and outRedirectCount
    // being set to 1 if found.
    statusFlags[3] = argc; // Store actual argument count

    return parsingError;
}


/* Built-in Command Handlers */

int handleCdCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags) {
    char targetDir[SHELL_MAX_PATH_LEN];
    char *oldPwd = getenv("PWD");
    
    if (statusFlags[2] > 0) {
        reportShellError(INVALID_REDIRECTION, NULL, NULL, NULL, "cd (output redirection)");
        return -1;
    }

    if(statusFlags[1] > 0) {
        if(args[1]) {
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, "cd (arguments with input redirection)");
            return -1;
        }
        
        FILE *inputFile = fopen(inputRedirects[0].fileName, "r");
        if(!inputFile) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, inputRedirects[0].fileName);
            return -1;
        }
        
        if(!fgets(targetDir, SHELL_MAX_PATH_LEN, inputFile)) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, inputRedirects[0].fileName);
            fclose(inputFile);
            return -1;
        }
        fclose(inputFile);
        
        targetDir[strcspn(targetDir, "\n")] = 0;
        // Use targetDir directly instead of assigning to args[1]
        if(chdir(targetDir) == -1) {
            reportShellError(DIRECTORY_ERROR, NULL, NULL, NULL, targetDir);
            return -1;
        }
    }
    // else if(statusFlags[1]) { // This condition is now redundant due to the previous 'if'
    //     reportShellError(INVALID_REDIRECTION, NULL, inputRedirects, statusFlags, "cd");
    //     return -1;
    // }

    // Determine target directory
    if(!args[1]) {
        // No argument - print current directory if no input redirection was given
        if (statusFlags[1] == 0) { // Only print if not from input redirect
            fprintf(stdout, "%s\n", oldPwd ? oldPwd : "");
        }
        return 0; // If no argument and no input redirect, print PWD and succeed
    }
    
    if(args[2]) {
        reportShellError(INVALID_ARGUMENT, args+2, NULL, NULL, "cd (too many arguments)");
        return -1;
    }

    // Change directory
    // Fix: Missing closing parenthesis in chdir call
    if(chdir(args[1]) == -1) { // chdir returns -1 on error
        reportShellError(DIRECTORY_ERROR, NULL, NULL, NULL, args[1]);
        return -1;
    }

    // Update PWD environment variable
    char newPwd[SHELL_MAX_PATH_LEN];
    if(!getcwd(newPwd, SHELL_MAX_PATH_LEN)) {
        reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "getcwd (failed to update PWD)");
        return -1;
    }
    setenv("PWD", newPwd, 1); // Overwrite PWD

    return 0;
}

void handleClearCommand(void) {
    pid_t pid = fork();
    if(pid == -1) {
        reportShellError(FORK_ERROR, NULL, NULL, NULL, "clear command fork failed");
    } else if(pid == 0) { // Child process
        execlp("clear", "clear", NULL);
        // If execlp fails, it returns -1. The child should exit.
        perror("execlp clear"); // Print error to stderr
        exit(1);
    } else { // Parent process
        waitpid(pid, NULL, 0); // Wait for the clear command to complete
    }
}


int handleDirCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags) {
    DIR *dir_ptr = NULL; 
    char dirPath[SHELL_MAX_PATH_LEN];
    
    // Check for input redirection case
    if(statusFlags[1] > 0) { // If input redirection is active
        if(args[1]) {
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, "dir (arguments with input redirection)");
            return -1;
        }
        
        FILE *inputFile = fopen(inputRedirects[0].fileName, "r");
        if(!inputFile) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, inputRedirects[0].fileName);
            return -1;
        }
        
        if(!fgets(dirPath, SHELL_MAX_PATH_LEN, inputFile)) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, inputRedirects[0].fileName);
            fclose(inputFile);
            return -1;
        }
        fclose(inputFile);
        
        // Remove newline if present
        dirPath[strcspn(dirPath, "\n")] = 0;
    } else { 
        if(!args[1]) {
            strcpy(dirPath, "."); // Default to current directory
        } else {
            if(args[2]) {
                reportShellError(INVALID_ARGUMENT, args+2, NULL, NULL, "dir (too many arguments)");
                return -1;
            }
            strncpy(dirPath, args[1], SHELL_MAX_PATH_LEN - 1);
            dirPath[SHELL_MAX_PATH_LEN - 1] = '\0'; // Ensure null-termination
        }
    }

    // Attempt to open directory to check if it exists and is accessible
    dir_ptr = opendir(dirPath);
    if(!dir_ptr) {
        reportShellError(DIRECTORY_ERROR, NULL, NULL, NULL, dirPath);
        return -1;
    }
    closedir(dir_ptr); // Close it, as ls will open it again.

    // List directory contents using ls
    pid_t pid = fork();
    if(pid == -1) {
        reportShellError(FORK_ERROR, NULL, NULL, NULL, "dir command fork failed");
        return -1;
    } else if(pid == 0) { // Child process
        // Execute 'ls -al <dirPath>'
        execlp("ls", "ls", "-al", dirPath, NULL);
        // If execlp fails, it returns -1. The child should exit.
        perror("execlp ls"); // Print error to stderr
        exit(1);
    } else { // Parent process
        waitpid(pid, NULL, 0); // Wait for ls to complete
    }
    
    return 0;
}


int handleEchoCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags) {
    // Check if there are arguments other than the command itself
    int hasArgs = (args[1] != NULL);
    
    // Handle input redirection case
    if(statusFlags[1] > 0) { // If input redirection is active
        if(hasArgs) { // Arguments provided with input redirection
            reportShellError(INVALID_ARGUMENT, args+1, NULL, NULL, "echo (arguments with input redirection)");
            return -1;
        }
        
        for(int i = 0; i < statusFlags[1]; i++) { // statusFlags[1] is 1 if input redirect exists
            FILE *inputFile = fopen(inputRedirects[i].fileName, "r"); // inputRedirects[0]
            if(!inputFile) {
                reportShellError(FILE_ERROR, NULL, NULL, NULL, inputRedirects[i].fileName);
                continue; // Try next input file if parsing allowed multiple
            }
            
            char buffer[SHELL_MAX_BUFFER];
            while(fgets(buffer, SHELL_MAX_BUFFER, inputFile)) {
                fputs(buffer, stdout); // fputs prints newline if buffer has one
            }
            fclose(inputFile);
        }
    } else { // No input redirection, just echo arguments
        // This check (statusFlags[1] again) is redundant if previous `if` block is correctly structured
        // if(statusFlags[1]) { // This condition is always false here
        //     reportShellError(INVALID_REDIRECTION, NULL, inputRedirects, statusFlags, "echo");
        //     return -1;
        // }
        
        // Print all arguments starting from args[1]
        for(int i = 1; args[i]; i++) {
            printf("%s", args[i]);
            if (args[i+1]) { // Add space between arguments, but not after the last one
                printf(" ");
            }
        }
        printf("\n"); // Always print a newline at the end of echo output
    }
    
    return 0;
}


int listEnvironmentVariables(void) {
    extern char **environ; // This declaration is fine here for accessing the global variable
    for(char **env = environ; *env; env++) {
        printf("%s\n", *env);
    }
    return 0;
}

int displayCurrentWorkingDirectory(void) {
    char cwd[SHELL_MAX_PATH_LEN]; // Use SHELL_MAX_PATH_LEN
    if(getcwd(cwd, sizeof(cwd)) != NULL) { // getcwd returns NULL on error
        printf("%s\n", cwd);
        return 0;
    } else {
        reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "getcwd");
        return -1;
    }
}

int displayHelp(char **args, const ShellRedirectInfo *outputRedirects, int *statusFlags) {
    const char *helpFilePath = "readme";

    if (statusFlags[1] > 0) {
        reportShellError(INVALID_REDIRECTION, NULL, NULL, NULL, "help (input redirection)");
        return -1;
    }
    // Check for output redirection - this is handled by executeSingleCommand,
    // so `displayHelp` should just print to stdout.

    // If 'help more' is requested
    if(args[1] && strcmp(args[1], "more") == 0) {
        if (args[2]) { // Check for extra arguments after 'more'
            reportShellError(INVALID_ARGUMENT, args+2, NULL, NULL, "help more (too many arguments)");
            return -1;
        }

        // Display entire help file via 'less' or 'more' command for paging
        pid_t pid = fork();
        if (pid == -1) {
            reportShellError(FORK_ERROR, NULL, NULL, NULL, "help more fork failed");
            return -1;
        } else if (pid == 0) { // Child process
            execlp("more", "more", helpFilePath, NULL); // Or "less"
            perror("execlp more/less");
            exit(1);
        } else { // Parent process
            waitpid(pid, NULL, 0);
        }
        return 0;
    }
    
    // Search for specific help topic
    FILE *helpFile = fopen(helpFilePath, "r");
     if(!helpFile) {
        reportShellError(FILE_ERROR, NULL, NULL, NULL, helpFilePath);
        return -1;
    }
    
    char searchTerm[100];
    // Construct search term: "<help topic>" or "<help>" for general help
    if(args[1]) {
        snprintf(searchTerm, sizeof(searchTerm), "<help %s>", args[1]);
    } else {
        strcpy(searchTerm, "<help>"); // General help marker
    }
    
    char buffer[SHELL_MAX_BUFFER];
    int found = 0;
    
    // Search for the topic marker
    while(fgets(buffer, sizeof(buffer), helpFile) != NULL) {
        if(strstr(buffer, searchTerm)) {
            found = 1;
            break;
        }
    }
    
    // Display help section
    if(found) {
        while(fgets(buffer, sizeof(buffer), helpFile) != NULL) {
            if(buffer[0] == '#') break; // Section end marker (assuming # on a new line marks end)
            fputs(buffer, stdout);
        }
    } else {
        reportShellError(HELP_NOT_FOUND, NULL, NULL, NULL, args[1] ? args[1] : "general");
    }
    
    fclose(helpFile);
    return 0;
}

int executeBatchFile(char **args, const ShellRedirectInfo *inputRedirects,
                     const ShellRedirectInfo *outputRedirects, int *statusFlags) {
    char batchFilePath[SHELL_MAX_PATH_LEN];
    FILE *batchFile = NULL;
    
    // Check for output redirection errors if 'myshell' command itself is redirected
    if (statusFlags[2] > 0) {
        reportShellError(INVALID_REDIRECTION, NULL, NULL, NULL, "myshell (output redirection for command itself)");
        return -1;
    }

    // Determine batch file path
    if (statusFlags[1] > 0) { // If input redirection is used for batch file
        if(args[1]) {
            fprintf(stderr, "Note: Only one input file can be specified for batch execution, using '%s'\n", inputRedirects[0].fileName);
        }
        getFullPath(batchFilePath, inputRedirects[0].fileName);
    } else if (args[1]) { // Batch file specified as an argument
        getFullPath(batchFilePath, args[1]);
    } else { // No batch file specified via argument or redirection
        // This means it's just 'myshell' or 'shell' without an argument.
        // The behavior here is printing version info as per your original code.
        printf("\nMyShell - Version 1.0\n");
        return 0;
    }
    
    // Check for recursive batch file execution
    // (This check assumes current_batch_file is correctly updated)
    if(is_batch_mode && strcmp(batchFilePath, current_batch_file) == 0) {
        fprintf(stderr, "Warning: Recursive batch file execution detected for '%s'. Skipping.\n", batchFilePath);
        return -1;
    }
    
    // Open batch file
    batchFile = fopen(batchFilePath, "r");
    if(!batchFile) {
        reportShellError(FILE_ERROR, NULL, NULL, NULL, batchFilePath);
        return -1;
    }
    
    // Set batch mode flags and execute
    int original_is_batch_mode = is_batch_mode; // Save original state
    char original_batch_file[SHELL_MAX_PATH_LEN];
    strncpy(original_batch_file, current_batch_file, SHELL_MAX_PATH_LEN);
    int original_batch_line_number = batch_line_number;

    is_batch_mode = 1;
    strncpy(current_batch_file, batchFilePath, SHELL_MAX_PATH_LEN);
    batch_line_number = 0; // Reset line number for new batch file
    fprintf(stderr, "Executing batch file: %s\n", current_batch_file);
    
    // `runShellLoop` handles the actual reading and execution of commands from the file.
    // It also handles its own output redirection within its scope.
    runShellLoop(batchFile, NULL, statusFlags); // Pass NULL for outputRedirects as runShellLoop handles it
    
    fclose(batchFile);
    fprintf(stderr, "Finished executing batch file: %s\n", current_batch_file);

    // Restore original batch mode state
    is_batch_mode = original_is_batch_mode;
    strncpy(current_batch_file, original_batch_file, SHELL_MAX_PATH_LEN);
    batch_line_number = original_batch_line_number;
    
    return 0;
}

/* Utility Functions */

int reportShellError(int errorType, char **args, const ShellRedirectInfo *ioRedirects,
                     const int *statusFlags, const char *message) {
    if(is_batch_mode) {
        fprintf(stderr, "Line %d of %s: ", batch_line_number, current_batch_file);
    }
    
    switch(errorType) {
        case COMMAND_NOT_FOUND:
            fprintf(stderr, "Command not found");
            if (args && args[0]) {
                fprintf(stderr, ": %s", args[0]);
            }
            fprintf(stderr, "\n");
            break;
            
        case INVALID_ARGUMENT:
            fprintf(stderr, "Invalid arguments");
            if (args && args[0]) {
                fprintf(stderr, " for command '%s'", message);
                for (int i = 0; args[i]; ++i) {
                     fprintf(stderr, " '%s'", args[i]);
                }
            }
            fprintf(stderr, "\n");
            break;
            
        case INVALID_REDIRECTION:
            fprintf(stderr, "Invalid I/O redirection for command: %s\n", message);
            break;
            
        case FILE_ERROR:
            fprintf(stderr, "Cannot open file: %s (Error: %s)\n", message, strerror(errno));
            break;
            
        case DIRECTORY_ERROR:
            fprintf(stderr, "Directory error: %s (Error: %s)\n", message, strerror(errno));
            break;
            
        case TOO_MANY_ARGUMENTS:
            fprintf(stderr, "Too many arguments (max %d allowed)\n", SHELL_MAX_ARGS - 1); // Max args is SHELL_MAX_ARGS-1 because of NULL terminator
            break;
            
        case TOO_MANY_REDIRECTIONS:
            fprintf(stderr, "Too many %s redirections (max %d allowed)\n",
                    message, SHELL_MAX_REDIRECT_FILES);
            break;
            
        case HELP_NOT_FOUND:
            fprintf(stderr, "No help found for topic: %s\n", message);
            break;
            
        case FORK_ERROR:
            fprintf(stderr, "Failed to create child process: %s\n", strerror(errno));
            break;
            
        case SYSTEM_ERROR:
            fprintf(stderr, "System error: %s (Error: %s)\n", message, strerror(errno));
            break;
            
        default:
            fprintf(stderr, "Unknown error: %s\n", message ? message : "No specific message");
    }
    
    return errorType;
}


int runShellLoop(FILE *inputFile, const ShellRedirectInfo *outputRedirects_main_loop, const int *statusFlags_main_loop) {
    char buffer[SHELL_MAX_BUFFER];
    
    // Only redirect output for the *entire* shell loop if `outputRedirects_main_loop` is provided
    int original_stdout = -1;
    if (outputRedirects_main_loop) {
        original_stdout = dup(STDOUT_FILENO); // Save original stdout
        int fd = open(outputRedirects_main_loop->fileName, (strcmp(outputRedirects_main_loop->openMode, "a") == 0) ? O_WRONLY | O_CREAT | O_APPEND : O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            reportShellError(FILE_ERROR, NULL, NULL, NULL, outputRedirects_main_loop->fileName);
            // Restore stdout if opening failed
            if (original_stdout != -1) dup2(original_stdout, STDOUT_FILENO);
            if (original_stdout != -1) close(original_stdout);
            return -1;
        }
        if (dup2(fd, STDOUT_FILENO) == -1) {
            reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "dup2 for stdout in shell loop");
            close(fd);
            if (original_stdout != -1) dup2(original_stdout, STDOUT_FILENO);
            if (original_stdout != -1) close(original_stdout);
            return -1;
        }
        close(fd); // Close the original file descriptor
    }
    
    batch_line_number = 0; // Reset for each new runShellLoop call
    
    // Prompt only in interactive mode
    if (inputFile == stdin) {
        printf("%s > ", getcwd(NULL, 0)); // Get current working directory for prompt
        fflush(stdout);
    }

    while(fgets(buffer, sizeof(buffer), inputFile) != NULL) {
        batch_line_number++;
        buffer[strcspn(buffer, "\n")] = 0; // Remove newline

        // Skip empty lines or lines with only whitespace
        if (strspn(buffer, SHELL_TOKEN_SEPARATORS) == strlen(buffer)) {
            if (inputFile == stdin) { // Reprompt in interactive mode
                printf("%s > ", getcwd(NULL, 0));
                fflush(stdout);
            }
            continue;
        }
        
        // Execute the command line
        // executeCommandLine already handles its own internal redirections and calls executeSingleCommand.
        // It's crucial that executeCommandLine returns 0 for success, -1 for error, and doesn't exit itself
        // unless it's the 'quit' command.
        if (executeCommandLine(buffer) == 1) { // 1 would signify 'quit' command for graceful exit
            break; // Exit loop if quit command was processed
        }

        if (inputFile == stdin) { // Reprompt in interactive mode
            printf("%s > ", getcwd(NULL, 0));
            fflush(stdout);
        }
    }
    
    // Restore stdout if it was redirected for the loop
    if (outputRedirects_main_loop && original_stdout != -1) {
        dup2(original_stdout, STDOUT_FILENO);
        close(original_stdout);
    }
    
    return 0;
}

void shellDelay(int seconds) {
    sleep(seconds);
}

void getFullPath(char *fullPath, const char *shortPath) {
    if (shortPath == NULL || fullPath == NULL) {
        if (fullPath) fullPath[0] = '\0'; // Ensure it's empty if invalid input
        return;
    }

    if (shortPath[0] == '~') {
        const char *home = getenv("HOME");
        if (home) {
            if (snprintf(fullPath, SHELL_MAX_PATH_LEN, "%s%s", home, shortPath + 1) >= SHELL_MAX_PATH_LEN) {
                reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "getFullPath: path truncated");
                fullPath[SHELL_MAX_PATH_LEN - 1] = '\0';
            }
        } else {
            strncpy(fullPath, shortPath, SHELL_MAX_PATH_LEN - 1);
            fullPath[SHELL_MAX_PATH_LEN - 1] = '\0';
        }
    } else if (shortPath[0] == '/') {
        strncpy(fullPath, shortPath, SHELL_MAX_PATH_LEN - 1);
        fullPath[SHELL_MAX_PATH_LEN - 1] = '\0';
    } else {
        char cwd[SHELL_MAX_PATH_LEN];
        if (getcwd(cwd, sizeof(cwd))) {
            if (snprintf(fullPath, SHELL_MAX_PATH_LEN, "%s/%s", cwd, shortPath) >= SHELL_MAX_PATH_LEN) {
                reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "getFullPath: path truncated");
                fullPath[SHELL_MAX_PATH_LEN - 1] = '\0';
            }
        } else {
            strncpy(fullPath, shortPath, SHELL_MAX_PATH_LEN - 1);
            fullPath[SHELL_MAX_PATH_LEN - 1] = '\0';
            reportShellError(SYSTEM_ERROR, NULL, NULL, NULL, "getcwd in getFullPath");
        }
    }

    fullPath[SHELL_MAX_PATH_LEN - 1] = '\0'; // Double-ensure null-termination
}


void handlePauseCommand(void) {
    // These static variables are from utility.c, so direct access is fine.
    if(is_batch_mode || is_background_batch) return; // Don't pause in batch or background mode
    
    printf("Press Enter to continue...");
    fflush(stdout); // Ensure prompt is displayed
    // Clear any pending input buffer first to prevent immediate unpause
    int c;
    while ((c = getchar()) != '\n' && c != EOF); // Consume existing newlines
    
    // Now wait for a new newline
    while(getchar() != '\n');
}
