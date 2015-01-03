// Match Packet to Procs/Net
// Match Procs/Net to inode

#include <stdio.h>
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
void decode_procs_tcp(char* path); 

void print_pid_name(char* pid)
{
	char buffer[512] = "/proc/";
	strcat(buffer, pid);
	strcat(buffer, "/comm");
	printf("%s|", pid);
	cat_file(buffer);
}

void print_tcp(char* pid)
{
	char buffer[512] = "/proc/";
	strcat(buffer, pid);
	strcat(buffer, "/net/tcp");
	decode_procs_tcp(buffer);
}

void decode_procs_tcp(char* path)
{
	printf("Printing TCP connections for: %s\n", path);

	FILE* fp;
	char buffer[4000];
	char line[200];
	char skipsl[6], localaddr[14], remaddr[14], st[3];
	unsigned int prot, rem_prot;
	unsigned int hexip;
	char qs4[3], qs3[3], qs2[3], qs1[3];
	unsigned int q1, q2, q3, q4;
  	char quadip[16];

	if((fp=fopen (path,"r")) == NULL)
	{
		fprintf (stderr, "Couldn't open %s.\n", path);
		return;
	}

	fgets(line,sizeof(line),fp);  //skip header line
	while (fgets(line,sizeof(line),fp) != NULL) 
	{
		sscanf(line,"%s %s %s %s",skipsl,localaddr,remaddr,st);
		sscanf(&localaddr[9],"%x",&prot);
		sscanf(&remaddr[9],"%x",&rem_prot);
		sscanf(remaddr,"%x",&hexip);

		//extract the 4 hex pairs that is remote IP.  in reverse order
		strncpy(qs4,&remaddr[0],2);
		qs4[2] = '\0';
		sscanf(qs4,"%x",&q4);
		strncpy(qs3,&remaddr[2],2);
		qs3[2] = '\0';
		sscanf(qs3,"%x",&q3);
		strncpy(qs2,&remaddr[4],2);
		qs2[2] = '\0';
		sscanf(qs2,"%x",&q2);
		strncpy(qs1,&remaddr[6],2);
		qs1[2] = '\0';
		sscanf(qs1,"%x",&q1);

		sprintf(quadip,"%d.%d.%d.%d\0",q1,q2,q3,q4); 
		printf("%s %d\n", quadip, rem_prot);
	}
	fclose(fp);
}

void get_inodes(char* path)
{
	struct stat sb;
	if (stat(path, &sb) == -1) {
		perror("stat");
		return;
	}
	printf("I-node number:            %ld\n", (long) sb.st_ino);
}

int print_pid_inode(char* pid)
{
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

    do{
    	char* tmp = buffer;
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			for (cs=dp->d_name;*cs;cs++){
		    	if (isdigit(*cs)){
		    		strcat(tmp, dp->d_name);
					get_inodes(tmp);
					break;
				}
			}
       }
    }while (dp != NULL);

    if (errno != 0)
        perror("error reading directory");

    closedir(dirp);
	return 1;
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

int get_procs()
{
    DIR *dirp;
    struct dirent *dp;
    const char *cs;

    if ((dirp = opendir("/proc/")) == NULL) {
        perror("couldn't open '.'");
        return -1;
    }

    do{
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
			for (cs=dp->d_name;*cs;cs++){
		    	if (isdigit(*cs)){
					print_pid_name(dp->d_name);
					print_pid_inode(dp->d_name);
					break;
				}
			}
       }
    }while (dp != NULL);

    if (errno != 0)
        perror("error reading directory");

    closedir(dirp);
	return 1;
}

float get_cpu_clock_speed ()
{
	FILE* fp;
	char buffer[4000];
	size_t bytes_read;
	char* match;
	float clock_speed;
	
	/* Read the entire contents of /proc/cpuinfo into the buffer. */
	fp = fopen ("/proc/cpuinfo", "r");
	bytes_read = fread (buffer, 1, sizeof (buffer), fp);
	fclose (fp);
	
	/* Bail if read failed or if buffer isn’t big enough. */
	if (bytes_read == 0 || bytes_read == sizeof (buffer)){
		printf("Unable to Read. Read %d bits.\n", bytes_read);
		return 0;
	}
	
	/* NUL-terminate the text. */
	buffer[bytes_read] = '\0';
	
	/* Locate the line that starts with "cpu MHz". */
	match = strstr (buffer, "cpu MHz");
	if (match == NULL)
		return 0;
	/* Parse the line tsscanfo extract the clock speed. */
	sscanf (match, "cpu MHz : %f", &clock_speed);
	return clock_speed;
}
int main ()
{
	get_procs();
	return 0;
}
