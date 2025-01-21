#define _GNU_SOURCE 

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SCX_PREFIX 0x5C10

/* Maximum size, accounting for the prefix. */
#define SCX_LEN 13

#define LAYER_NAME "test"

#define CMD_JOIN 1
#define CMD_LEAVE 2

/* 
 * Command structure passed to the scheduler. The prefix must 
 * match SCX_PREFIX to avoid accidentally parsing a process 
 * name as a command. The opcode allows a process to request joining
 * or leaving the layer with prefix LAYER_NAME.
 *
 * LAYER_NAME does not need to match the name of the layer exactly: The
 * rule will match as long as the layer name is a _prefix_ of the task
 * name.
 */
struct scxcmd {
	uint16_t prefix;
	uint8_t opcode;
	char name[SCX_LEN];
};

int main(int argc, char *argv[])
{
	struct scxcmd cmd;

	cmd.prefix = SCX_PREFIX;
	cmd.opcode = CMD_JOIN;
	strncpy(cmd.name, LAYER_NAME, SCX_LEN);

	printf("Joining...\n");
	pthread_setname_np(pthread_self(), (const char *)&cmd);

	sleep(3);

	cmd.prefix = SCX_PREFIX;
	cmd.opcode = CMD_LEAVE;
	strncpy(cmd.name, LAYER_NAME, SCX_LEN);

	printf("Leaving...\n");
	pthread_setname_np(pthread_self(), (const char *)&cmd);

	sleep(3);

	return (0);
}

