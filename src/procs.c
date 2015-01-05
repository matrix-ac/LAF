#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// TODO: Replace all strcat /proc/&/ with MACROS

void cat_file(char* dir);
void print_tcp(char* path);
void print_procs_tcp(char* path); 
char *hex_ip_str(char* hex_ip);
const char *get_inode_pid_string(unsigned long inode);
const char *get_pid_string(char *pid);
unsigned long get_inode(char* path); 
int get_pid_inode(char* pid, unsigned long inode); 

void print_tcp(char* pid)
{
	char buffer[512] = "/proc/";
	strcat(buffer, pid);
	strcat(buffer, "/net/tcp");
	print_procs_tcp(buffer);
}

void print_procs_tcp(char* path)
{
	printf("Printing TCP connections for: %s\n", path);

	FILE* fp;
	char buffer[4000];
	char line[200];

    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], timers[64], /*buffer[1024],*/ more[512];

	if((fp=fopen (path,"r")) == NULL)
	{
		fprintf (stderr, "Couldn't open %s.\n", path);
		return;
	}

	fgets(line,sizeof(line),fp);  // Skip header line

	while(fgets(line,sizeof(line),fp) != NULL) 
	{
		// TODO: Structure this. 
    	sscanf(line,
    		"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
		 		&d, local_addr, &local_port, rem_addr, &rem_port, &state,
				&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

		// printf("%s:%d -> %s:%d %ld %d\n", hex_ip_str(local_addr), local_port, hex_ip_str(rem_addr), rem_port, inode, uid);

	}
	fclose(fp);
}

int proc_tcp_has_inode(unsigned long search_inode)
{
	FILE* fp;
	char buffer[4000];
	char line[1024];

    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout, rtn = 1; 
    char rem_addr[128], local_addr[128], timers[64], more[512];
    char path[] = "/proc/net/tcp";

	if((fp=fopen (path,"r")) == NULL)
	{
		fprintf (stderr, "Couldn't open %s.\n", path);
		return rtn;
	}

	fgets(line,sizeof(line),fp);  // Skip header line

	while(fgets(line,sizeof(line),fp) != NULL) 
	{
		// TODO: Structure this. 
    	sscanf(line,
    		"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
		 		&d, local_addr, &local_port, rem_addr, &rem_port, &state,
				&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
    	if(inode == search_inode)
    	{
			printf("%s:%d -> %s:%d state %d (inode %ld, uid %d)\n", hex_ip_str(local_addr), local_port, hex_ip_str(rem_addr), rem_port, state, inode, uid);
    		rtn = EXIT_SUCCESS;
    	}

	}
	fclose(fp);
	return rtn;
}

/* Parse the PID's FD, return when it finds a match for the inode.  */
int get_pid_inode(char* pid, unsigned long target_inode)
{
	int rtn = EXIT_FAILURE;

	char buffer[512] = "/proc/";
	strcat(buffer, pid);
	strcat(buffer, "/fd/");
	
    DIR *dirp;
    struct dirent *dp;
    const char *cs;

    if ((dirp = opendir(buffer)) == NULL) {
        perror("couldn't open file.");
        return -1;
    }

    char tmp[512] = "";
    // unsigned long ret = 0;
    memcpy(tmp, buffer, 512);
    do{
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			for (cs=dp->d_name;*cs;cs++){
				if (isdigit(*cs)) {
		    		strcat(tmp, dp->d_name);
					if(get_inode(tmp) == target_inode){
						// printf("%s (%ld)\n", get_pid_string(pid), ret);
						rtn = EXIT_SUCCESS;
						dp = NULL;
					}
				}		
			}
       }
       memcpy(tmp, buffer, 512);
    }while (dp != NULL);

    if (errno != 0)
        perror("error reading directory");

    closedir(dirp);
	return rtn;
}

void cat_file(char* dir)
{
	FILE* fp;
	char buffer[4000];
	size_t bytes_read;

	fp = fopen (dir, "r");
	bytes_read = fread (buffer, 1, sizeof (buffer), fp);
	fclose (fp);
	
	/* Bail if read failed or if buffer isn’t big enough. */
	if (bytes_read == 0 || bytes_read == sizeof (buffer)){
		printf("Unable to Read. Read %d bits.\n", bytes_read);
	}
	
	/* NUL-terminate the text. */
	buffer[bytes_read] = '\0';
	// printf("Opening Dir: %s\n", dir);
	printf("%s\n", buffer);
}

/* ==================================================================================== */

const char *get_inode_pid_string(unsigned long inode)
{
	const char *rtn = "Unknown INODE";

	/* Parse all the PIDs in proc */
    DIR *dirp;
    struct dirent *dp;
    const char *cs;

    if ((dirp = opendir("/proc/")) == NULL) {
        perror("couldn't open '.'");
        return NULL;
    }

    do{
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			for (cs=dp->d_name;*cs;cs++){
		    	if (isdigit(*cs)){
					if(get_pid_inode(dp->d_name, inode) == EXIT_SUCCESS){
						rtn = get_pid_string(dp->d_name);
						dp = NULL;
					}
					break;
				}
			}
       }
    }while(dp != NULL);

    if (errno != 0) {
    	perror("error reading directory");
    }

    closedir(dirp);

	return rtn;
}

const char *get_pid_string(char *pid)
{
	FILE* fp;
	char line[1024];
	const char *rtn = "Unknown";

	char path[256]; 
	sprintf(path,"/proc/%s/comm\0", pid);

	if ((fp = fopen(path,"r")) == NULL)
	{
		fprintf(stderr, "Couldn't open file path [%s]. (get_pid_string)\n", path);
		return rtn;
	}

	if (fgets(line, sizeof(line), fp) != NULL)
	{		
		//sscanf(line, "%[A-Za-z0-9]s", rtn);
		rtn = line; // BUG Causes segfault on some binary names.
	}
	fclose(fp);
	return rtn;
}

unsigned long get_inode(char* path)
{
	struct stat sb;
	if (stat(path, &sb) == -1) {
		// perror("stat");
		return -1;
	}
	switch (sb.st_mode & S_IFMT) {
		case S_IFSOCK: return (long) sb.st_ino;
			break;
		default: //printf("Not A socket\n");
			break;
	}
	return -1;
}

const char* net_to_pid_name(char* ip_src, uint16_t src_port, char* ip_dst, uint16_t dst_port)
{
	FILE* fp;
	char buffer[4000];
	char line[1024];
	const char *rtn = NULL;

    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout; 
    char rem_addr[128], local_addr[128], timers[64], more[512];
    char path[] = "/proc/net/tcp";

	if((fp=fopen (path,"r")) == NULL)
	{
		fprintf (stderr, "Couldn't open %s.\n", path);
		return rtn;
	}

	fgets(line,sizeof(line),fp);  // Skip header line

	while(fgets(line,sizeof(line),fp) != NULL) 
	{
    	sscanf(line,
    		"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
		 		&d, local_addr, &local_port, rem_addr, &rem_port, &state,
				&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);

    	if(strcmp(hex_ip_str(local_addr), ip_src) == 0 && strcmp(hex_ip_str(rem_addr), ip_dst) == 0
    		&& local_port == src_port && rem_port == dst_port)
    	{
			printf("[>] State %d (inode %ld, uid %d)\n", state, inode, uid);
			rtn = get_inode_pid_string(inode);
    	}
	}

	fclose(fp);
	free(ip_src);
	free(ip_dst);

	return rtn;
}

/* Convert the reversed HEX IP address to string */
char* hex_ip_str(char* hex_ip)
{
	char qs4[3], qs3[3], qs2[3], qs1[3];
	unsigned int q1, q2, q3, q4;
  	char quadip[16];

	// Extract the 4 hex pairs in reverse order.
	strncpy(qs4, &hex_ip[0], 2);
	qs4[2] = '\0';
	sscanf(qs4,"%x",&q4);
	strncpy(qs3, &hex_ip[2], 2);
	qs3[2] = '\0';
	sscanf(qs3,"%x",&q3);
	strncpy(qs2, &hex_ip[4], 2);
	qs2[2] = '\0';
	sscanf(qs2,"%x",&q2);
	strncpy(qs1, &hex_ip[6], 2);
	qs1[2] = '\0';
	sscanf(qs1, "%x", &q1);

	sprintf(quadip,"%d.%d.%d.%d\0",q1,q2,q3,q4);

	char* return_ip = (char*)malloc(sizeof(quadip));
	if(return_ip == NULL) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}
	return strncpy(return_ip, quadip, sizeof(quadip));
}

// int main() {
// 	get_procs();
// }