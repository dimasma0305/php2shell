Output docs/demo/php2shell-codeigniter.gif
Output docs/demo/php2shell-codeigniter.mp4

Require python3
Require tee

Set Shell bash
Set Width 1280
Set Height 720
Set FontSize 18
Set TypingSpeed 20 ms
Set Framerate 30
Set PlaybackSpeed 2.0
Set Theme "Catppuccin Mocha"
Set Padding 16
Set Margin 24
Set MarginFill "#11111b"
Set WindowBar ColorfulRight
Set BorderRadius 8
Set CursorBlink false

Hide
Type "exec > >(tee docs/demo/php2shell-codeigniter-proof.txt) 2>&1"
Enter
Type "python3 scripts/demo_loopback_proxy.py >/tmp/php2shell-demo-proxy.log 2>&1 &"
Enter
Sleep 1s
Type "clear"
Enter
Show

Type "python3 -u poc.py --url http://127.0.0.1:18087/ --retries 1"
Enter
Sleep 45s
Enter
Sleep 2s
