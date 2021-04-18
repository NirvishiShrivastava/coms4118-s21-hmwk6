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
					printf("PID matched with subdirectory : %s\n",d_path);
					strcat(subdir_name,d_path);
					break;
				}
			}
		}
		closedir(d);
	}

	if(chdir(subdir_name)== -1)
		perror("Error changing directory");
	/*
	system("/bin/ls > /dev/null");
	*/
	/* Read total */
	fp = fopen("total", "r");
	printf("Reading Files in Directory: %s\n",subdir_name);
	
	if (fp == NULL) {
		perror("Error while opening the file");
		exit(EXIT_FAILURE);
	}

	printf("# of Total Pages: ");
	while((ch = fgetc(fp)) != EOF)
		printf("%c", ch);
	
	fclose(fp);

	/* Read Zero */
	fp = fopen("zero", "r");
    
    	if (fp == NULL) {
		perror("Error while opening the file.\n");
		exit(EXIT_FAILURE);
	}

	printf("# of Zero Pages: ");
	while((ch = fgetc(fp)) != EOF)
		printf("%c", ch);
    
	fclose(fp);
    
}

int main(int argc, char *argv[])
{
	int pid;

	if(argc != 2) {
		printf("Usage: ./inspect_pages pid\n");
		return 1;
	}

	pid = atoi(argv[1]);
	do_inspect_pages(pid);

	return 0;

}
