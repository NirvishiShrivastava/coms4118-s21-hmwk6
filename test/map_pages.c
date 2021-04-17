#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>

#define PAGE_SIZE 0x1000UL

int main(void)
{
	int pid, p_pid;
	void *addr;
	unsigned long size = PAGE_SIZE * 10;
	char inspect_pages[30];

	p_pid = fork();
	
	if (p_pid == 0) {
		pid = getpid();
		
		sprintf(inspect_pages,"./inspect_pages %d",pid);		
		addr = malloc(size);
		
		if (!addr)
			return -ENOMEM;
		
		/* Allocating zero pages */
		memset(addr, 0, size);
		system(inspect_pages);
		
		printf("\nPress enter to transform few pages to non-zero pages:");
		getchar();
		fflush(stdin);
		
		memset(addr, 'a', PAGE_SIZE * 4);
		system(inspect_pages);		
		
		printf("\nPress enter to scrub pages back to zero pages:");
		getchar();
		fflush(stdin);
		
		memset(addr, 0, size);
		system(inspect_pages);		
				
		free(addr);
		return 0;

	} else if (p_pid > 0) {
		wait(NULL);
	} else {
		printf("fork() failed.\n");
	}
	return 0;   
}
