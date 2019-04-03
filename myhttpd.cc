const char * usage =
"usage: myhttpd [-f|-t|-p]  [<port>]\n"
"    Where 1024 < port < 65536.\n"
"    -f: Create a new process for each request\n"
"    -t: Create a new thread for each request\n"
"    -p:  Pool of threads\n";

#include <chrono>
#include <sys/types.h>
#include <bits/stdc++.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <netdb.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

int port;
int QueueLength = 5;
int mode = 0; // -f = 1, -t = 2, -p = 3
extern char **environ;
// Processes time request
pthread_mutex_t mutex;
pthread_mutexattr_t mattr;
struct tm * timeinfo;
int countRequest = 0;
long double maxtime = 0;
char maxurl[512] = {0};
char minurl[512] = {0};
long double mintime = 2000000000;
FILE * logs;
FILE * stats;
extern "C" void killzombie(int sig);
typedef void(*httprunfunc)(int ssock, const char* querystring);

void processDisplayRequest( int socket );
void *loopthread (int fd);
void poolOfThreads( int masterSocket );
void dispatchHTTP(int fd);

struct fileInfo{
	std::string type;
	std::string path;
	std::string name;
	std::string time;
	std::string size;
};
extern "C" void killzombie(int sig)
{
	int pid = 1;//= wait3(0, 0, NULL);
	while(waitpid(-1, NULL, WNOHANG) > 0);
}
bool compNamei(fileInfo f1, fileInfo f2){
	return(f1.name<f2.name);
}
bool compTimei(fileInfo f1, fileInfo f2){
	return(f1.time<f2.time);
}
bool compSizei(fileInfo f1, fileInfo f2){
	return(f1.size<f2.size);
}
bool compNamed(fileInfo f1, fileInfo f2){
	return(f1.name>f2.name);
}
bool compTimed(fileInfo f1, fileInfo f2){
	return(f1.time<f2.time);
}
bool compSized(fileInfo f1, fileInfo f2){
	return(f1.size>f2.size);
}
void dispatchHTTP(int fd){
	processDisplayRequest(fd);
	close(fd);
}

void poolOfThreads( int masterSocket ) {
	pthread_t thread[5];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);            

	for (int i=0; i<4; i++) {
		pthread_create(&thread[i], NULL, (void* (*)(void*))loopthread, (void *)masterSocket);
	}
	loopthread (masterSocket);
}

void *loopthread (int fd) {
	while (1) {
		pthread_mutex_lock(&mutex);
		struct sockaddr_in clientIPAddress;
		int alen = sizeof( clientIPAddress );
		int slaveSocket = accept( fd,(struct sockaddr *)&clientIPAddress,(socklen_t*)&alen);
		pthread_mutex_unlock(&mutex);
		if (slaveSocket >= 0) {
			dispatchHTTP(slaveSocket);
		}
	}
}

void displayDir( int mode, char* cwd, int socket){
	DIR *dir;
	struct dirent *ent;
	printf("mode: %d\n",mode);
	std::string ns = "C=N;O=A",ms = "C=M;O=A",ss = "C=S;O=A",ds = "C=D;O=A";
	if(mode == 0){
		ns= "C=N;O=D";
	}
	if(mode == 2){
		ms= "C=M;O=D";
	}
	if(mode == 4){
		ss= "C=S;O=D";
	}
	if(mode == 6){
		ds ="C=D;O=D";
	}
	if ((dir = opendir (cwd)) != NULL) {
		const char *protocol = "HTTP/1.0 200 Document follows";
		const char *crlf = "\r\n";
		const char *server = "Server: CS 252 lab5/1.0";
		const char *content_type = "Content-type: ";

		write(socket, protocol, strlen(protocol));
		write(socket, crlf, strlen(crlf));
		write(socket, server, strlen(server));
		write(socket, crlf, strlen(crlf));
		write(socket, content_type, strlen(content_type));
		write(socket, crlf, strlen(crlf));
		write(socket, crlf, strlen(crlf));
		//save the icons
		char blank[512] = {0};
		strcpy(blank,"/icons/blank.gif");
		//printf("%s\n",blank);
		char htmltext[1024];
		sprintf(htmltext, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html>\n<head>\n<title>Index of /homes/cs252/lab5-http-server/lab5-src/http-root-dir/htdocs/dir1</title>\n</head>\n<body>\n<h1>Index of /homes/cs252/lab5-http-server/lab5-src/http-root-dir/htdocs/dir1</h1>\n<table>\n"); 
		write(socket,htmltext,strlen(htmltext));
		sprintf(htmltext, "<tr><th valign=\"top\"><img src=\"%s\" alt=\"[ICO]\"></th><th><a href=\"?%s\">Name</a></th><th><a href=\"?%s\">Last modified</a></th><th><a href=\"?%s\">Size</a></th><th><a href=\"?%s\">Description</a></th></tr>\n<tr><th colspan=\"5\"><hr></th></tr>\n",blank,ns.c_str(),ms.c_str(),ss.c_str(),ds.c_str());
		write(socket,htmltext,strlen(htmltext));
		char * temp = strstr(cwd, "/subdir");
		if(temp){
			sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"/icons/back.gif\" alt=\"[PARENTDIR]\"></td><td><a href=\"./\">Parent Directory</a></td><td>&nbsp;</td><td align=\"right\">  - </td><td>&nbsp;</td></tr>");
		}else{
			sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"/icons/back.gif\" alt=\"[PARENTDIR]\"></td><td><a href=\"../\">Parent Directory</a></td><td>&nbsp;</td><td align=\"right\">  - </td><td>&nbsp;</td></tr>");
		}
		write(socket,htmltext,strlen(htmltext));
		std::vector<fileInfo> fileVec;
		std::vector<fileInfo> folderVec;
		while ((ent = readdir (dir)) != NULL) {
			char file[512] = {0};
			strcpy(file, cwd);
			char * temp = strstr(file, "/dir");
			if(temp[strlen(temp)-1] != '/'){
				strcat(temp,"/");
			}
			strcpy(file, "/htdocs/");
			strcat(file,temp);
			strcat(file, ent->d_name);
			if(strncmp(ent->d_name, ".", 1) != 0 ){

				char abs[512] = {0};
				strcpy(abs, cwd);
				//strcat(abs, "/");
				strcat(abs, ent->d_name);
				struct stat attr;
				stat(abs, &attr);
				float fileSize = (float)attr.st_size/1000.0;
				struct tm *tm;
				tm = localtime(&attr.st_mtime);
				char timeinc[512]= {0};
				sprintf(timeinc,"%d-%d-%d %d:%d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
				//printf("%s\n",timeinc);
				char type[512] = {0};
				int isdir = 0;
				strcpy(type,"/icons/");
				if(strstr(ent->d_name, ".gif") != 0){
					strcat(type, "image.gif");
				}else if(strstr(ent->d_name, "dir") != 0){
					isdir = 1;
					strcat(abs, "/");
					strcat(type, "menu.gif");
					temp = strstr(file, "/dir");
					strcpy(file,temp);
					fileSize = -1;
				}else{
					strcat(type, "unknown.gif");
				}
				char filesi[512];
				if(fileSize == -1){
					sprintf(filesi, "-");
				}else{
					sprintf(filesi, "%.2f K", fileSize);
				}
				fileInfo tbp;
				std::string inter(type);
				std::string inter1(file);
				std::string inter2(ent->d_name);
				std::string inter3(timeinc);
				std::string inter4(filesi);
				if(isdir){
					folderVec.push_back({inter,inter1,inter2,inter3,inter4});
				}else{
					fileVec.push_back({inter,inter1,inter2,inter3,inter4});
				}
			}
		}
	//0:NA 1:ND
	//2:MA 3:MD
	//4:SA 5:SD
		if(mode == 0){
			std::sort(fileVec.begin(), fileVec.end(), compNamei); 
			std::sort(folderVec.begin(), folderVec.end(), compNamei); 
		}
		if(mode == 1){
			std::sort(fileVec.begin(), fileVec.end(), compNamed); 
			std::sort(folderVec.begin(), folderVec.end(), compNamed); 
		}
		if(mode == 2){
			std::sort(fileVec.begin(), fileVec.end(), compTimei); 
			std::sort(folderVec.begin(), folderVec.end(), compTimei); 
		}
		if(mode == 3){
			std::sort(fileVec.begin(), fileVec.end(), compTimed); 
			std::sort(folderVec.begin(), folderVec.end(), compTimed); 
		}
		if(mode == 4){
			std::sort(fileVec.begin(), fileVec.end(), compSizei); 
			std::sort(folderVec.begin(), folderVec.end(), compSizei); 
		}
		if(mode == 5){
			std::sort(fileVec.begin(), fileVec.end(), compSized); 
			std::sort(folderVec.begin(), folderVec.end(), compSized); 
		}
		if(mode == 6){
			std::sort(fileVec.begin(), fileVec.end(), compNamei); 
			std::sort(folderVec.begin(), folderVec.end(), compNamei); 
		}
		if(mode == 7){
			std::sort(fileVec.begin(), fileVec.end(), compNamed); 
			std::sort(folderVec.begin(), folderVec.end(), compNamed); 
		}
		if(mode == 0 || mode == 2 || mode == 5 || mode == 6) {
			for(int i = 0; i < fileVec.size(); i++){
				fileInfo forprint;
				forprint = fileVec[i];
				sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"%s\" alt=\"[   ]\"></td><td><a href=\"%s\">%s</a></td><td align=\"right\">%s </td><td align=\"right\"> %s</td><td>&nbsp;</td></tr>\n", forprint.type.c_str(), forprint.path.c_str(), forprint.name.c_str(), forprint.time.c_str(), forprint.size.c_str());
				write(socket,htmltext,strlen(htmltext));
			}
			for(int i = 0; i < folderVec.size(); i++){
				fileInfo forprint;
				forprint = folderVec[i];
				sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"%s\" alt=\"[   ]\"></td><td><a href=\"%s\">%s</a></td><td align=\"right\">%s </td><td align=\"right\"> %s</td><td>&nbsp;</td></tr>\n", forprint.type.c_str(), forprint.path.c_str(), forprint.name.c_str(), forprint.time.c_str(), forprint.size.c_str());
				write(socket,htmltext,strlen(htmltext));
			}
		}
		if(mode == 1 || mode == 3 || mode == 4 || mode == 7){
			for(int i = 0; i < folderVec.size(); i++){
				fileInfo forprint;
				forprint = folderVec[i];
				sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"%s\" alt=\"[   ]\"></td><td><a href=\"%s\">%s</a></td><td align=\"right\">%s </td><td align=\"right\"> %s</td><td>&nbsp;</td></tr>\n", forprint.type.c_str(), forprint.path.c_str(), forprint.name.c_str(), forprint.time.c_str(), forprint.size.c_str());
				write(socket,htmltext,strlen(htmltext));
			}
			for(int i = 0; i < fileVec.size(); i++){
				fileInfo forprint;
				forprint = fileVec[i];
				sprintf(htmltext, "<tr><td valign=\"top\"><img src=\"%s\" alt=\"[   ]\"></td><td><a href=\"%s\">%s</a></td><td align=\"right\">%s </td><td align=\"right\"> %s</td><td>&nbsp;</td></tr>\n", forprint.type.c_str(), forprint.path.c_str(), forprint.name.c_str(), forprint.time.c_str(), forprint.size.c_str());
				write(socket,htmltext,strlen(htmltext));
			}
		}
		sprintf(htmltext, "<tr><th colspan=\"5\"><hr></th></tr>\n</table>\n<address>Apache/2.4.18 (Ubuntu) Server at data.cs.purdue.edu Port 10160</address>\n</body></html>");
		write(socket,htmltext,strlen(htmltext));
		closedir (dir);

	} else {
		perror ("");
		exit(-1);
	}
}
void soModule(int socket, char* cwd, char* cgi){
	void * lib = dlopen(cwd, RTLD_LAZY);
	if(lib != NULL){
		httprunfunc httprun;
		httprun = (httprunfunc) dlsym(lib, "httprun");
		if(httprun != NULL){
			const char *protocol = "HTTP/1.0 200 Document follows";
			const char *crlf = "\r\n";
			const char *server = "Server: CS 252 lab5/1.0";
			const char *content_type = "Content-type: ";

			write(socket, protocol, strlen(protocol));
			write(socket, crlf, strlen(crlf));
			write(socket, server, strlen(server));
			write(socket, crlf, strlen(crlf));
			httprun(socket, cgi);
		}else{
			write(socket, "HTTP/1.1 404 File Not Found", 27);
			write(socket, "\r\n", 2);
			write(socket, "Server: cs 252", 14);
			write(socket, "\r\n", 2);
			write(socket, "Content-type: text/html", 23);
			write(socket, "\r\n", 2);
			write(socket, "\r\n", 2);
			write(socket, "File not found", 14);
		}
	}else{
			write(socket, "HTTP/1.1 404 File Not Found", 27);
			write(socket, "\r\n", 2);
			write(socket, "Server: cs 252", 14);
			write(socket, "\r\n", 2);
			write(socket, "Content-type: text/html", 23);
			write(socket, "\r\n", 2);
			write(socket, "\r\n", 2);
			write(socket, "File not found", 14);
	}
}

	void
processDisplayRequest( int socket )
{
	//TODO
	//mutex
	auto begin= std::chrono::system_clock::now();

	pthread_mutex_lock(&mutex);
	countRequest++;
	pthread_mutex_unlock(&mutex);


	char n;


	// Currently character read
	char newChar;
	char oldChar = 0;
	char currString[1024] = {0};
	int length = 0;
	int gotGET = 0;
	char docPath[1024] = {0};
	char ll = ' ';
	char lll = ' ';
	// Last character read
	while((n = read(socket, &newChar, sizeof(newChar)))>0 && length < 1024){
		if(newChar == ' '){
			if(gotGET == 0){
				gotGET = 1;
			}else if(gotGET == 1){
				currString[length]=0;
				strcpy(docPath, currString);
				gotGET = 2;
			}
		}else if(newChar == '\n' && oldChar == '\r' && ll == '\n' && lll == '\r'){
			break;
		}else{
			lll=ll;
			ll=oldChar;
			oldChar = newChar;
			if(gotGET == 1){
				currString[length] = newChar;
				length++;
			}
		}
	}
	//printf("im here\n");
	char cwd[512] = {0};
	getcwd(cwd,sizeof(cwd));
	char cgi[4096] = {0};
	int isdir = 0;
	int iscgi = 0;
	int mode = 0;
	//0:NA 1:ND
	//2:MA 3:MD
	//4:SA 5:SD
	//printf("here\n");
	if(strncmp(docPath, "/icons", strlen("/icons")) == 0 || strncmp(docPath, "/htdocs", strlen("/htdocs")) == 0){
		strcat(cwd, "/http-root-dir/");
		strcat(cwd, docPath);
	}else if(strncmp(docPath, "/cgi-bin", strlen("/cgi-bin")) == 0){
		strcat(cwd, "/http-root-dir/");
		//strcat(cwd, docPath);
		iscgi = 1;
		//printf("%s\n",docPath);
		if(strstr(docPath, "?")!=0){
			char * temp = strstr(docPath, "?");
			memcpy(cgi, &temp[1], strlen(temp)-1 );
			strncat(cwd, docPath,strlen(docPath) - strlen(cgi) - 1);
		}else{
			strcpy(cgi,"");
			strcat(cwd, docPath);
		}
		if(strstr(docPath, ".so")!=0){
			soModule(socket, cwd, cgi);
			close(socket);
			return;
		}
	}else if(strcmp(docPath, "/") == 0){
		strcat(cwd, "/http-root-dir/");
		strcat(cwd, "htdocs/index.html");
	}else if(strncmp(docPath, "/dir", strlen("/dir")) == 0){
		isdir = 1;
		strcat(cwd, "/http-root-dir/htdocs");
		char newPath [512] = {0};
		if(strstr(docPath, "C=N;O=A") != 0){
			mode = 0;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=N;O=D") != 0){
			mode = 1;
			strncpy (newPath, docPath, strlen(docPath)-8);
		}else if(strstr(docPath, "C=M;O=A") != 0){
			mode = 2;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=M;O=D") != 0){
			mode = 3;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=S;O=A") != 0){
			mode = 4;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=S;O=D") != 0){
			mode = 5;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=D;O=A") != 0){
			mode = 6;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else if(strstr(docPath, "C=D;O=D") != 0){
			mode = 7;
			strncpy (newPath, docPath,strlen(docPath)- 8);
		}else{
		strcpy (newPath, docPath);
		}
		//printf("mode is %d,docPath is %s\n",mode,newPath);

		strcat(cwd, newPath);
		
	}else{
		strcat(cwd, "/http-root-dir/");
		strcat(cwd, "htdocs");
		strcat(cwd,docPath);
	}

	char hostname[512] = {0};
	if(gethostname(hostname,sizeof(hostname))==0){
		logs = fopen("./http-root-dir/htdocs/logs", "a");
		fprintf(logs, "%s:%d %s\n", hostname,port, docPath);
		fclose(logs);
	}

	if(strstr(docPath, "..") != 0){
		char temp[1024] = {0};
		char *ye = realpath(cwd, temp);
		if(ye){
			if(strlen(temp)>=strlen(cwd)+21){
				strcpy(cwd,temp);
			}
		}
	}
	printf("cwd is: %s\n",cwd);
	//get type
	int isImage = 0;
	char contentType[1024];
	if (strstr(docPath, ".html") != 0)
	{
		strcpy(contentType, "text/html");
	}
	else if (strstr(docPath, ".jpg") != 0)
	{
		strcpy(contentType, "image/jpeg");
		isImage = 1;
	}
	else if (strstr(docPath, ".gif") != 0)
	{
		strcpy(contentType, "image/gif");
		isImage = 1;
	}
	else
	{
		strcpy(contentType, "text/plain");
	}

	FILE * fd;
	if(isdir == 0 && iscgi == 0){
		fd = fopen(cwd, "rb");


		if(fd>0)
		{
			//printf("here");
			const char *protocol = "HTTP/1.0 200 Document follows";
			const char *crlf = "\r\n";
			const char *server = "Server: CS 252 lab5/1.0";
			const char *content_type = "Content-type: ";

			write(socket, protocol, strlen(protocol));
			write(socket, crlf, strlen(crlf));
			write(socket, server, strlen(server));
			write(socket, crlf, strlen(crlf));
			write(socket, content_type, strlen(content_type));
			write(socket, crlf, strlen(crlf));
			write(socket, contentType, strlen(contentType));
			write(socket, crlf, strlen(crlf));
			write(socket, crlf, strlen(crlf));
			long count = 0;
			char c;
			while (count = read(fileno(fd), &c, sizeof(c))){
				if (count != write(socket, &c, sizeof(c))){
					//perror("write");
				}
			}
			fclose(fd);
		}else{
			write(socket, "HTTP/1.1 404 File Not Found", 27);
			write(socket, "\r\n", 2);
			write(socket, "Server: cs 252", 14);
			write(socket, "\r\n", 2);
			write(socket, "Content-type: text/html", 23);
			write(socket, "\r\n", 2);
			write(socket, "\r\n", 2);
			write(socket, "File not found", 14);
		}
	}else if(isdir == 1){
		//printf("call from here");
		displayDir(mode,cwd, socket);
	}else if(iscgi == 1){
		printf("env: %s\n",getenv("QUERY_STRING"));
		printf("cgi: %s\n",cgi);
		int ret = fork();
		int defout = dup(1);
		dup2(socket, 1);
		if (ret == 0){
			setenv("REQUEST_METHOD", "GET", 1);
			setenv("QUERY_STRING", cgi, 1);
			const char *protocol = "HTTP/1.0 200 Document follows";
			const char *crlf = "\r\n";
			const char *server = "Server: CS 252 lab5/1.0";
			const char *content_type = "Content-type: ";

			write(socket, protocol, strlen(protocol));
			write(socket, crlf, strlen(crlf));
			write(socket, server, strlen(server));
			write(socket, crlf, strlen(crlf));
			//write(socket, crlf, strlen(crlf));
			std::vector<char*> chararg{};
			chararg.push_back(const_cast<char*>(cgi));
			printf("cwd: %s, cgi: %s\n", cwd, chararg.data()[0]);
			execvp(cwd, chararg.data());
		}else{
			waitpid(ret, NULL, 0);
		}
		dup2(defout, 1);
		close(defout);
	}
	auto end= std::chrono::system_clock::now();;
	auto duration= end-begin;
	typedef std::chrono::duration<long double,std::ratio<1,1000>> MyMilliSecondTick;
  	MyMilliSecondTick milli(duration);
  	if(milli.count() > maxtime){
  		maxtime = milli.count();
  		strcpy(maxurl, docPath);
  	}
  	if(milli.count() < mintime){
  		mintime = milli.count();
  		strcpy(minurl, docPath);
  	}
  	stats = fopen("./http-root-dir/htdocs/stats", "w");
	fprintf(stats, "Student Name: Tianyu Zhao (zhao 684).\nServer set up time: %s",asctime(timeinfo));
	fprintf(stats, "Number of requests since the server started: %d\n",countRequest);
	fprintf(stats, "minimum service time is %Lf ms when the URL is %s\n", mintime,minurl);
	fprintf(stats, "maximum service time is %Lf ms when the URL is %s\n", maxtime,maxurl);
	fclose(stats);
  	//printf("%Lf\n",milli.count());
	//printf("%s",request);
	//fclose(fd);
}


	int
main( int argc, char ** argv )
{
	// Print usage if not enough arguments
	if ( argc < 2 ) {
		fprintf( stderr, "%s", usage );
		exit( -1 );
	}

	// Get the port from the arguments

	if(argc > 1 && argv[1][0] == '-'){
		port = atoi( argv[2] );
		if(argv[1][1] == 'f'){
			mode = 1;
		}else if(argv[1][1] == 't'){
			mode = 2;
		}else if(argv[1][1] == 'p'){
			mode = 3;
		}else{
			fprintf(stderr, "%s", usage);
			exit(-1);
		}
	}else{
		port = atoi( argv[1] );
		mode = 0;
	}
	// Set the IP address and port for this server
	struct sockaddr_in serverIPAddress; 
	memset( &serverIPAddress, 0, sizeof(serverIPAddress) );
	serverIPAddress.sin_family = AF_INET;
	serverIPAddress.sin_addr.s_addr = INADDR_ANY;
	serverIPAddress.sin_port = htons((u_short) port);


	// Allocate a socket
	int masterSocket =  socket(PF_INET, SOCK_STREAM, 0);
	if ( masterSocket < 0) {
		perror("socket");
		exit( -1 );
	}

	// Set socket options to reuse port. Otherwise we will
	// have to wait about 2 minutes before reusing the sae port number
	int optval = 1; 
	int err = setsockopt(masterSocket, SOL_SOCKET, SO_REUSEADDR, 
			(char *) &optval, sizeof( int ) );

	// Catch the zombie processes
	struct sigaction signalAction;

	signalAction.sa_handler = killzombie;
	sigemptyset(&signalAction.sa_mask);
	signalAction.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &signalAction, NULL)) {
		perror("sigaction");
		exit(-1);
	}
	// Bind the socket to the IP address and port
	int error = bind( masterSocket,
			(struct sockaddr *)&serverIPAddress,
			sizeof(serverIPAddress) );
	if ( error ) {
		perror("bind");
		exit( -1 );
	}

	// Put socket in listening mode and set the 
	// size of the queue of unprocessed connections
	error = listen( masterSocket, QueueLength);
	if ( error ) {
		perror("listen");
		exit( -1 );
	}

	time_t rawtime;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );

	if(mode == 3){
		poolOfThreads( masterSocket );
	}else{
		while ( 1 ) {

			// Accept incoming connections
			struct sockaddr_in clientIPAddress;
			int alen = sizeof( clientIPAddress );
			int slaveSocket = accept( masterSocket,
					(struct sockaddr *)&clientIPAddress,
					(socklen_t*)&alen);

			if ( slaveSocket < 0 ) {
				perror( "accept" );
				exit( -1 );
			}
			//printf("mode is %d\n",mode);
			if(mode == 1){//new process for each request

				//printf("mode is 1\n");
				int ret = fork();
				if(ret == 0){
					processDisplayRequest(slaveSocket);
					close(slaveSocket);
					exit(0);
				}
				close(slaveSocket);
			}else if(mode == 2){//new thread
				//printf("mode is 2\n");
				//if (slaveSocket >= 0) {
				// When the thread ends resources are recycled
				pthread_t thread;
				pthread_attr_t attr;
				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
				pthread_create(&thread, &attr, (void* (*)(void*))dispatchHTTP, (void *) slaveSocket);
				//}
			}else{
				//printf("mode is 0\n");
				processDisplayRequest( slaveSocket );
				close(slaveSocket);
			}
		}
	}
	//fclose(stats);
}

/*
   main()
   {
// Add your HTTP implementation here


}*/
