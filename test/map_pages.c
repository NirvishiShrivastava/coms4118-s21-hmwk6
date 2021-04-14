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
//TODO: Implement do_inspect_pages function
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
