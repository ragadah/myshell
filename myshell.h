#ifndef MYSHELL_H
#define MYSHELL_H

#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>   
#include <unistd.h>   
#include <sys/types.h>
#include <sys/wait.h> 
#include <errno.h>    
#include <dirent.h>   
#include <ctype.h>    // For character type testing (isspace, isdigit)
#include <fcntl.h>    // For file control options (open, close, etc.)
#include <signal.h>   // For signal handling (though not extensively used yet)


#define SHELL_MAX_BUFFER 1024       // Maximum size for command line input
#define SHELL_MAX_ARGS 64           // Maximum number of arguments per command
#define SHELL_TOKEN_SEPARATORS " \t\n" // Characters used to split tokens (arguments)
#define SHELL_MAX_REDIRECT_FILES 10 // Max number of I/O redirection files (stdin/stdout)
#define SHELL_MAX_PATH_LEN 256      // Maximum length for file and directory paths (Increased for better practice)

// --- Error Codes (CRITICAL: ADD THIS ENUM) ---
typedef enum {
    COMMAND_NOT_FOUND = 1,
    INVALID_ARGUMENT,
    INVALID_REDIRECTION,
    FILE_ERROR,
    DIRECTORY_ERROR,
    TOO_MANY_ARGUMENTS,
    TOO_MANY_REDIRECTIONS,
    HELP_NOT_FOUND,
    FORK_ERROR,
    SYSTEM_ERROR
} ShellErrorType;


// Structure to hold information about I/O redirections
typedef struct {
    char *fileName;    // Name of the file for redirection
    char openMode[3];  // File open mode (e.g., "r" for read, "w" for write, "a" for append)
    char operator[3];  // Redirection operator (e.g., "<" input redirection, ">" output redirection, ">>" output append)
} ShellRedirectInfo;


// --- Function Prototypes (from utility.c and main.c) ---
int executeCommandLine(char *commandLine); 
int executeSingleCommand(char **args, const ShellRedirectInfo *inputRedirects,
                         const ShellRedirectInfo *outputRedirects, int *statusFlags); 

int parseCommandLine(char *buffer, char **args, int *statusFlags,
                     ShellRedirectInfo *inputRedirects, ShellRedirectInfo *outputRedirects); 

int handleCdCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags); 
void handleClearCommand(void); // Implemented in utility.c
int handleDirCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags); 
int handleEchoCommand(char **args, const ShellRedirectInfo *inputRedirects, int *statusFlags); 
int listEnvironmentVariables(void); 
int displayCurrentWorkingDirectory(void); 
int displayHelp(char **args, const ShellRedirectInfo *outputRedirects, int *statusFlags); 
int executeBatchFile(char **args, const ShellRedirectInfo *inputRedirects,
                     const ShellRedirectInfo *outputRedirects, int *statusFlags); 

int reportShellError(int errorType, char **args, const ShellRedirectInfo *ioRedirects,
                     const int *statusFlags, const char *message);
int runShellLoop(FILE *inputFile, const ShellRedirectInfo *outputRedirects, const int *statusFlags); 
void shellDelay(int seconds); 
void getFullPath(char *fullPath, const char *shortPath); 
void handlePauseCommand(void); 

#endif // MYSHELL_H
