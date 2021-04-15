#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#define PAGE_SIZE 0x1000UL

void do_inspect_pages(int pid)
{
    char subdir_name[30] = "/mnt/";
    FILE *fp;
    DIR *d;
    char *token_pid;
    char ch, s[2] = ".", pid_str[10];
    struct dirent *dir;

    sprintf(pid_str,"%d",pid);
    
    /* extract sub directory name from pid */
    d = opendir("/mnt");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            printf("%s\n", dir->d_name);
            token_pid = strtok(dir->d_name, s);
            
            if(strcmp(token_pid,pid_str) == 0) {
                /* Form subdir path */
                strcat(subdir_name,dir->d_name);
                break;
            }
        }
        closedir(d);
    }
        
    /* Read total pages*/
    fp = fopen(strcat(subdir_name,"/total"), "r");
    
    if (fp == NULL) {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    
    while((ch = fgetc(fp)) != EOF)
        printf("%c\n", ch);
    
    fclose(fp);
    
    /* Read Zero */
    /*fp = fopen(strcat(subdir_name,"/zero"), "r");
    
    if (fp == NULL) {
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    
    while((ch = fgetc(fp)) != EOF)
        printf("%c\n", ch);
    
    fclose(fp); */
    
}


int main(void)
{
    int pid, p_pid;
    void *addr;
    unsigned long size = PAGE_SIZE * 10;
    
    p_pid = fork();
    if (p_pid == 0) {
        pid = getpid();
        
        // TODO: Check if we can malloc or need to mmap
        addr = malloc(size);
        if (!addr)
            return -ENOMEM;
        
        // Allocating zero pages
        memset(addr, 0, size);
        
        do_inspect_pages(pid);
        
        printf("Press enter to transform few pages to non-zero pages:\n");
        getchar();
        fflush(stdin);
        
        memset(addr, 'a', PAGE_SIZE * 4);
        
        do_inspect_pages(pid);
        
        printf("Press enter to scrub pages back to zero pages:\n");
        getchar();
        fflush(stdin);
        
        memset(addr, 0, size);
        
        do_inspect_pages(pid);
        
        sleep(30);
        free(addr);
        return 0;
        
    } else if (p_pid > 0) {
            wait(NULL);
    } else {
            printf("fork() failed.\n");
    }
    return 0;
    
}
