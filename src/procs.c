/*
    This file is part of Linux Application Firewall (LAF).

    Linux Application Firewall (LAF) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    Linux Application Firewall (LAF) is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Linux Application Firewall (LAF).  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <arpa/inet.h>  
#include <sys/stat.h>
#include <unistd.h>

#include "procs.h"

/* Takes IP_SRC SRC_PORT, IP_DST DST_PORT and returns a string of the associated binary name with the socket. */
const char* net_to_pid_name(char* ip_src, uint16_t src_port, char* ip_dst, uint16_t dst_port)
{
	FILE* fp;
	char line[LINE_BUFFER_SIZE];
	const char *rtn = NULL;

    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout; 
    char rem_addr[128], local_addr[128], more[512];
    char path[] = "/proc/net/tcp";

	if((fp=fopen (path,"r")) == NULL)
	{
		fprintf(stderr, "Couldn't open file path [%s]. (net_to_pid_name)\n", path);
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

/* Convert the reversed HEX IP address to a string */
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

	sprintf(quadip,"%d.%d.%d.%d",q1,q2,q3,q4);

	char* return_ip = (char*)malloc(sizeof(quadip));
	if(return_ip == NULL) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}
	return strncpy(return_ip, quadip, sizeof(quadip));
}

/* Takes an I-node number, and returns the name of the binary associated with it */
const char *get_inode_pid_string(unsigned long inode)
{
	const char *rtn = "Unknown INODE";

	/* Parse all the PIDs in proc */
    DIR *dirp;
    struct dirent *dp;
    // const char *cs;

    if ((dirp = opendir("/proc/")) == NULL) {
		fprintf(stderr, "Couldn't open file path [/proc/]. (get_inode_pid_string)\n");
        return NULL;
    }

    do{
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			// for (cs=dp->d_name;*cs;cs++){
			// 	if (isdigit(*cs)){
					if(get_pid_inode(dp->d_name, inode) == EXIT_SUCCESS){
						rtn = get_pid_string(dp->d_name);
						// printf("[#] Yes there is a binary matching the Inode.\n");
						dp = NULL;
					}
			// 	}
			// }
       }
    }while(dp != NULL);

    if (errno != 0) {
    	perror("error reading directory");
    }

    closedir(dirp);

	return rtn;
}

/* Parse the PID's FD, returns when it finds a match for the inode. */
int get_pid_inode(char* pid, unsigned long target_inode)
{
	int rtn = EXIT_FAILURE;

	char buffer[MAX_PATH_LENGTH] = "/proc/";
	strcat(buffer, pid);
	strcat(buffer, "/fd/");
	
    DIR *dirp;
    struct dirent *dp;
    const char *cs;

    if ((dirp = opendir(buffer)) == NULL) {
		// fprintf(stderr, "Couldn't open file path [%s]. (get_pid_inode)\n", buffer); // TODO Commented out to make output nicer. It
        return -1;
    }

    char tmp[MAX_PATH_LENGTH] = "";
    // unsigned long ret = 0;
    memcpy(tmp, buffer, MAX_PATH_LENGTH);
    do{
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			for (cs=dp->d_name;*cs;cs++){
				if (isdigit(*cs)) {
		    		strcat(tmp, dp->d_name);
					if(get_inode(tmp) == target_inode){
						// printf("%s (%ld)\n", get_pid_string(pid), target_inode);
						rtn = EXIT_SUCCESS;
						// dp = NULL;
					}
				}		
			}
       }
       memcpy(tmp, buffer, MAX_PATH_LENGTH);
    }while (dp != NULL);

    if (errno != 0)
        perror("error reading directory");

    closedir(dirp);
	return rtn;
}

/* Takes a PID and returns it's string name */
const char *get_pid_string(char *pid)
{
	FILE* fp;
	char line[LINE_BUFFER_SIZE];
	const char *rtn = "Unknown PID String";

	char path[MAX_PATH_LENGTH]; 
	sprintf(path,"/proc/%s/cmdline", pid);

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

/* Returns the inode of the passed file path */
unsigned long get_inode(char* path)
{
	struct stat sb;
	if (stat(path, &sb) == -1) {
		// perror("stat"); // TODO Handel Error.
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
