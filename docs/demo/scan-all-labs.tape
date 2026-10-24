# VHS v0.12.1. Start all documented loopback labs before rendering.
# This tape types and runs the passive scanner live; it does not replay output.
Output docs/demo/scan-all-labs.gif
Output docs/demo/scan-all-labs.mp4
Output docs/demo/scan-all-labs.ascii

Set Shell pwsh
Set Width 1600
Set Height 620
Set FontSize 18
Set TypingSpeed 5 ms

Type "python scan.py --assets assets.txt"
Enter
Wait+Screen@45s /summary/
Sleep 2s
