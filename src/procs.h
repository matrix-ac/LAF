#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* Takes IP_SRC SRC_PORT, IP_DST DST_PORT and returns a string of the associated binary name with the socket. */
const char* net_to_pid_name(char* ip_src, uint16_t src_port, char* ip_dst, uint16_t dst_port);
/* Convert the reversed HEX IP address to a string */
char* hex_ip_str(char* hex_ip);
/* Takes an I-node number, and returns the name of the binary associated with it */
const char *get_inode_pid_string(unsigned long inode);
/* Parse the PID's FD, returns when it finds a match for the inode. */
int get_pid_inode(char* pid, unsigned long target_inode);
/* Takes a PID and returns it's string name */
const char *get_pid_string(char *pid);
/* Returns the inode of the passed file path */
unsigned long get_inode(char* path);