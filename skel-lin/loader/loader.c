/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "exec_parser.h"

int file_descriptor;
static so_exec_t *exec;

/* 
* method that reads data previously written to a file with read function
* verifies if it was intrerupted by a signal and returns a suitable error code
*/
void read_to_mem(int page_number, int i, char *memory_allocation)
{
	int bytes_read;

	/*
	* check if the file starts when a page starts
	*/
	if (page_number != (exec->segments[i].file_size / 4096)) {
		/*
		* reading the bytes from the file
		*/
		bytes_read = read(file_descriptor, memory_allocation, 4096);

		/* 
		* if the read function is interrupted by a signal in the second part of
		* the file(size), that means it wants to access the bss file, and it
		* needs to be filled with 0 
		*/
		if (bytes_read > 1023 && bytes_read < 2048) {
			/*
			* initialise the bss section with 0
			*/
			for (int j = 0; j < 4096; j++) {
				memory_allocation[j] = 0;
			}
		}

		if (bytes_read == -1) {
			DIE(bytes_read == -1, "read failed");
			exit(4);
		}
	} else if (page_number == (exec->segments[i].file_size / 4096)) {
		if (exec->segments[i].file_size % 4096 == 0) {
			/*
			* reading the bytes from the file
			*/
			bytes_read = read(file_descriptor, memory_allocation, 4096);

			/*
			* initialise the bss section with 0
			*/
			for(int j = 0; j < 4096; j++)
				memory_allocation[j] = 0;

			if (bytes_read == -1) {
				DIE(bytes_read == -1, "read failed");
				exit(3);
			}
		} else {
			/*
			* reading the bytes from the file
			*/
			bytes_read = read(file_descriptor, memory_allocation, exec->segments[i].file_size % 4096);
			if (bytes_read == -1) {
				DIE(bytes_read == -1, "read failed");
				exit(2);
			}
		}
	}
}

/*
* method that maps the pages in memory and verifies what is the cause of the
* page fault, and then returns a suitable error code
*/
static void segv_handler(int signum, siginfo_t *info, void *context)
{
	char *fault, *memory_allocation, *err_mmap;
	int page_number;
	int flag = 0;
	int rc;

	fault = info->si_addr;
	for (int i = 0; i < exec->segments_no; i++) {
		if (exec->segments[i].vaddr <= (unsigned int)fault &&
			exec->segments[i].vaddr + exec->segments[i].mem_size
			> (unsigned int)fault) {
			page_number = (int)(fault -  exec->segments[i].vaddr) / 4096;
			if (((char *)exec->segments[i].data)[page_number] != 1) {
				flag = 1;
				memory_allocation = (char *)((exec->segments[i].vaddr) +
											page_number * 4096);

				int offset_location = lseek(file_descriptor, page_number * 4096 +
						exec->segments[i].offset,
						SEEK_SET);
				DIE(offset_location == -1, "lseek failed");

				err_mmap = mmap(memory_allocation, 4096, PROT_READ | PROT_WRITE
								| PROT_EXEC, MAP_FIXED | MAP_PRIVATE
								| MAP_ANONYMOUS, -1, 0);

				if (!err_mmap) {
					DIE(1, "mmap failed");
					exit(10);
				}

				memset((char *)memory_allocation, 0, 4096);
				((char *)exec->segments[i].data)[page_number]= 1;
				DIE(memset((char *)memory_allocation, 0, 4096) == NULL,
					"memset failed");

				read_to_mem(page_number, i, memory_allocation);

				rc = mprotect(memory_allocation, 4096,
						exec->segments[i].perm);
				if (rc == -1) {
					DIE(1, "mprotect failed");
					exit(5);
				}
			} else {
				flag = 1;
				signal(signum, SIG_DFL);
				kill(getpid(), signum);
			}
		}
	}

	if (flag == 0) {
		signal(signum, SIG_DFL);
		kill(getpid(), signum);
	}

}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	DIE(memset(&sa, 0, sizeof(sa)) == NULL, "memset failed");

	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	exec = so_parse_exec(path);

	for (int i = 0; i < exec->segments_no; i++) {
		exec->segments[i].data = (void *)calloc(1000, 1);
		DIE(exec->segments[i].data == NULL, "calloc failed");
	}

	for (int i = 0; i < exec->segments_no; i++) {
		free(exec->segments[i].data);
	}
	
	file_descriptor = open(path, O_RDONLY);
	DIE(file_descriptor == -1, "open failed");

	so_start_exec(exec, argv);
	close(file_descriptor);
	
	return -1;
}
