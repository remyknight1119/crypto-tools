#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "lib.h"
#include "tool.h"
#include "proto.h"
#include "comm.h"

static const char *
ct_program_version = "1.0.0";//PACKAGE_STRING;

static const struct option 
ct_long_opts[] = {
	{"help", 0, 0, 'H'},
	{"inpiut", 0, 0, 'i'},
	{"output", 0, 0, 'o'},
	{"key", 0, 0, 'k'},
	{"random", 0, 0, 'r'},
	{"filter", 0, 0, 'f'},
	{0, 0, 0, 0}
};

static const char *
ct_options[] = {
	"--input        -i	input file\n",	
	"--output       -o	output file path\n",	
	"--key          -k	private key file\n",	
	"--random       -r	random number file\n",	
    "--port         -p  filter port\n",
	"--filter       -F	use filter\n",	
	"--help         -H	Print help information\n",	
};

static void 
ct_help(void)
{
	int     index;

	fprintf(stdout, "Version: %s\n", ct_program_version);

	fprintf(stdout, "\nOptions:\n");
	for(index = 0; index < CT_ARRAY_SIZE(ct_options); index++) {
		fprintf(stdout, "  %s", ct_options[index]);
	}
}

static const char *
ct_optstring = "HFi:o:k:r:p:";

int
main(int argc, char **argv)  
{
    char            *input = NULL;
    char            *output = NULL;
    char            *key = NULL;
    char            *random = NULL;
    char            *filter = NULL;
    char            filter_buf[CT_CMD_BUF_SIZE] = {};
    int             c = 0;
    int             ret = 0;

    while((c = getopt_long(argc, argv, 
                    ct_optstring,  ct_long_opts, NULL)) != -1) {
        switch(c) {
            case 'H':
                ct_help();
                return 0;
            case 'F':
                filter = filter_buf;
                break;

            case 'i':
                input = optarg;
                break;

            case 'o':
                output = optarg;
                break;

            case 'k':
                key = optarg;
                break;

            case 'r':
                random = optarg;
                break;

            case 'p':
                snprintf(&filter_buf[0], sizeof(filter_buf), "port %s", optarg);
                break;

            default:
                ct_help();
                return 1;
        }
    }

    if (input == NULL) {
        fprintf(stderr, "Please input the input file by -i\n");
        return 1;
    }

    if (output == NULL) {
        fprintf(stderr, "Please input the output file path by -o\n");
        return 1;
    }

    if (key == NULL && random == NULL) {
        fprintf(stderr, "Please input the key file by -k\n");
        return 1;
    }

    proto_init();

    ret = ct_decrypt_file(output, input, key, random, filter);
    if (ret != 0) {
        fprintf(stderr, "Decrypt file %s failed!\n", input);
        return 1;
    }

    return 0;
}
