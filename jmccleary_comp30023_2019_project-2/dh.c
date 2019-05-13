/* A simple client program for server.c

   To compile: gcc client.c -o client

   To run: start the server, then the client */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>


// Function to compute a^m mod n. Method obtained from https://www.techiedelight.com/c-program-demonstrate-diffie-hellman-algorithm/
int compute(int a, int g, int p)
{
	int r;
	int y = 1;

	while (g > 0)
	{
		r = g % 2;

		// fast exponention 
		if (r == 1)
			y = (y*a) % p;
		a = a*a % p;

		g = g / 2;
	}

	return y;
}


int main(int argc, char ** argv)
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent * server;

    char buffer[256];

    if (argc < 3)
    {
        fprintf(stderr, "usage %s hostname port\n", argv[0]);
        exit(0);
    }

    portno = atoi(argv[2]);


    /* Translate host name into peer's IP address ;
     * This is name translation service by the operating system
     */
    server = gethostbyname(argv[1]);

    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    /* Building data structures for socket */

    bzero((char *)&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;

    bcopy(server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);

    serv_addr.sin_port = htons(portno);

    /* Create TCP socket -- active open
    * Preliminary steps: Setup: creation of active open socket
    */

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(0);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR connecting");
        exit(0);
    }

    bzero(buffer, 256);
    sprintf(buffer, "jmccleary\n");
    printf("Username is:%s", buffer);
    n = write(sockfd, buffer, strlen(buffer));
    bzero(buffer, 256);
    int mysecretint = 61;
    printf("My secret int is: %d\n", mysecretint);
    int mysecretkey = compute(15, mysecretint, 97);
    char *mysecretkeystr;
    sprintf(mysecretkeystr, "%d", mysecretkey);
    sprintf(buffer, "%s\n", mysecretkeystr);
    printf("My secret key is: %s", buffer);
    n = write(sockfd, buffer, strlen(buffer));
    

    bzero(buffer, 256);

    n = read(sockfd, buffer, 255);

    if (n < 0)
    {
        perror("ERROR reading from socket");
        exit(0);
    }
    
    char *serverkeystr = buffer;
    int serverkey = (int)strtol(serverkeystr, NULL, 10);
    int sharedkey = compute(serverkey, mysecretint, 97);
    printf("Server key is: %s", buffer);
    char sharedkeystr[256];
    sprintf(sharedkeystr, "%d\n", sharedkey);
    bzero(buffer, 256);
    sprintf(buffer, "%s", sharedkeystr);
    printf("Shared key is: %s", buffer);
    write(sockfd, buffer, strlen(buffer));
    bzero(buffer, 256);
    read(sockfd, buffer, 255);
    printf("%s\n", buffer);

    return 0;
}