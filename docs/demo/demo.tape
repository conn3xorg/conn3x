Output .github/assets/demo.gif

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1400
Set Height 760
Set Padding 24
Set TypingSpeed 35ms
Set Theme { "name": "Conn3x", "black": "#0f1a2b", "red": "#ff8a7a", "green": "#7fd3a7", "yellow": "#ffb86b", "blue": "#8fb3ff", "magenta": "#d6a5ff", "cyan": "#7fd8e6", "white": "#dbe4ef", "brightBlack": "#5d6f88", "brightRed": "#ff9a8c", "brightGreen": "#9be3bf", "brightYellow": "#ffc98a", "brightBlue": "#a9c4ff", "brightMagenta": "#e2bdff", "brightCyan": "#9fe5ef", "brightWhite": "#f3f6fa", "background": "#0f1a2b", "foreground": "#dbe4ef", "selection": "#2a3b55", "cursor": "#ff7a2e" }

Hide
Type "export PS1='$ ' PATH=$PWD:$PATH; alias web1='ssh -q -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1'; clear" Enter
Sleep 500ms
Show

Type "cat web.circuit.hcl" Sleep 300ms Enter
Sleep 3s
Type "conn3x apply -auto-approve -compact-warnings" Sleep 300ms Enter
Sleep 6s
Type "web1 cat /etc/motd" Sleep 300ms Enter
Sleep 2s
Type "web1 'echo hacked > /etc/motd'" Sleep 300ms Enter
Sleep 1s
Type "clear; conn3x plan" Sleep 300ms Enter
Sleep 6s
