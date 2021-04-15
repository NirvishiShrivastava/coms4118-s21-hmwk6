#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>

#define PAGE_SIZE 0x1000UL

void do_inspect_pages(int pid)
{
	FILE *fp;
	DIR *d;
	char ch, pid_str[50], d_path[260], *token_pid, subdir_name[100] = "/mnt/";
	struct dirent *dir;
	
	sprintf(pid_str,"%d",pid);
	
	/* extract sub directory name from pid */
	d = opendir("/mnt");
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			/* Exclude . and .. directories */
			if(dir->d_type == DT_DIR && strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0) {
				sprintf(d_path,"%s", dir->d_name);
				token_pid = strtok(dir->d_name,".");
				
				if(strcmp(token_pid,pid_str) == 0) {
					// Form subdir path
					printf("\nPID matched with subdirectory : %s\n",d_path);
					strcat(subdir_name,d_path);
					break;
				}
			}
		}
		closedir(d);
	}
	
	/* Read total */
	strcat(subdir_name,"/total");
	fp = fopen(subdir_name, "r");
	printf("File opening - %s\n",subdir_name);
	
	if (fp == NULL) {
		perror("Error while opening the file");
		exit(EXIT_FAILURE);
	}
	
	while((ch = fgetc(fp)) != EOF)
		printf("%c", ch);
	
	fclose(fp);
    
    /* Read Zero 
    fp = fopen(strcat(subdir_name,"/zero"), "r");
    
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
		addr = malloc(size);
		
		if (!addr)
			return -ENOMEM;
		
		// Allocating zero pages
		memset(addr, 'a', size);
		do_inspect_pages(pid);
        
/*        printf("Press enter to transform few pages to non-zero pages:\n");
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
  */      
	} else if (p_pid > 0) {
		wait(NULL);
	} else {
		printf("fork() failed.\n");
	}
	return 0;
   
}
