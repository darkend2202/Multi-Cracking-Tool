import argparse
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import pikepdf
import hashlib
from pyfiglet import Figlet
from colorama import init, Fore, Style

init(autoreset=True)

def print_banner(text="My Tool", font="slant", color=Fore.CYAN):
    f = Figlet(font=font)
    art = f.renderText(text)
    print(color + art + Style.RESET_ALL)

if __name__ == "__main__":

    TOOL_NAME = "Cracker"
    VERSION = "v2.0"
    print_banner(f"{TOOL_NAME} {VERSION}", font="slant", color=Fore.GREEN)
    print(Fore.YELLOW + "Author: darkend.")
    print(Fore.MAGENTA + "Use responsibly. Authorized testing only.\n")


def generate_passwords(chars, min_length, max_length):
    for length in range(min_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            yield ''.join(password)

def custom_wordlist(chars, min_length, max_length, filename):
    # create the file and return number of entries written
    total_combinations = sum(len(chars) ** length for length in range(min_length, max_length + 1))
    print(f'[*] Character set:{chars}\n[*] File Name:{filename}\n[*] Total Generating Passwords:{total_combinations}')
    count = 0
    with open(filename, "w", encoding="utf-8") as f:
        with tqdm(total=total_combinations, desc="Generating wordlist", unit="pw") as pbar:
            for length in range(min_length, max_length + 1):
                for pw in itertools.product(chars, repeat=length):
                    f.write("".join(pw) + "\n")
                    count += 1
                    pbar.update(1)  # Update progress bar each password

        return count

def load_passwords(wordlist_file):
    with open(wordlist_file, 'r', encoding='utf-8') as file:
        for line in file:
            yield line.strip()

def try_password(pdf_file, password):
    try:
        with pikepdf.open(pdf_file, password=password) as pdf:
            return password
    except pikepdf._core.PasswordError:
        return None

def count_generated_total(chars, min_length, max_length):
    base = len(chars)
    total = 0
    for L in range(min_length, max_length+1):
        total += base ** L
    print(f'[*] Character Set:{chars}')
    return total

def crack_pdf_with_generator(pdf_file, passwords_iter, total, max_workers=4):
    batch_size = 1000
    it = iter(passwords_iter)
    checked = 0
    print(f'[*] Target Pdf File:{pdf_file}\n[*] Total Passwords:{total}')
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        with tqdm(total=total, desc="Trying passwords", unit="pw") as pbar:
            while True:
                futures = []
                for _ in range(batch_size):
                    try:
                        pwd = next(it)
                    except StopIteration:
                        break
                    futures.append(executor.submit(try_password, pdf_file, pwd))
                if not futures:
                    break
                for fut in as_completed(futures):
                    checked += 1
                    pbar.update(1)
                    result = fut.result()
                    if result:

                        executor.shutdown(wait=False)
                        return result
    return None

def iter_file_batches(path, batch_size=1000):
    with open(path, 'rb') as fh:
        batch = []
        for raw in fh:
            line = raw.decode('utf-8', errors='replace').rstrip('\r\n')
            batch.append(line)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

def crack_pdf_with_file(pdf_file, wordlist_file, max_workers=4, total=None, batch_size=1000):
    if total is None:
        with open(wordlist_file, 'rb') as f:
            total = sum(1 for _ in f)

    print(f'[*] Target Pdf File:{pdf_file}\n[*] Wordlist File:{wordlist_file}\n[*] Total Passwords:{total}')

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        with tqdm(total=total, desc="Trying passwords", unit="pw") as pbar:

            for batch in iter_file_batches(wordlist_file, batch_size=batch_size):

                futures = {executor.submit(try_password, pdf_file, pwd): pwd for pwd in batch}

                for fut in as_completed(futures):
                    result = fut.result()
                    pbar.update(1)

                    if result:
                        for other in futures:
                            if not other.done():
                                other.cancel()
                        return result

    return None

hash_name = [
    'sha3_224',
    'sha224',
    'sha384',
    'shake_256',
    'blake2b',
    'sha256',
    'sm3',
    'sha512_224',
    'sha3_256',
    'blake2s',
    'md5-sha1',
    'ripemd160',
    'sha3_384',
    'sha512',
    'shake_128',
    'sha3_512',
    'sha512_256',
    'md5',
    'sha1'
]


def hsgenerate_passwords(min_length, max_length, characters):
    for length in range(min_length, max_length + 1):
        for pwd in itertools.product(characters, repeat=length):
            yield ''.join(pwd)


def check_hash(hash_fn, password, target_hash):
    return hash_fn(password.encode()).hexdigest() == target_hash


def crack_hash(hash, wordlist=None, hash_type='md5', min_length=0, max_length=0,
               characters=string.ascii_letters + string.digits, max_workers=4):
    hash_fn = getattr(hashlib, hash_type, None)
    if hash_fn is None or hash_type not in hash_name:
        raise ValueError(f'[!] Invalid hash type: {hash_type} supported are {hash_name}')

    if wordlist:
        with open(wordlist, "rb") as f:
            total = sum(1 for _ in f)

        print(f"[*] Target Hash:{hash}")
        print(f"[*] Total Passwords:{total}")
        print(f"[*] Wordlist:{wordlist}")
        print(f"[*] Hash Type:{hash_type}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=total, desc="Cracking hash", unit="pw") as pbar:
                with open(wordlist, "rb") as f:
                    for raw in f:
                        pwd = raw.decode("utf-8", errors="replace").strip()

                        future = executor.submit(check_hash, hash_fn, pwd, hash)

                        if future.result():  # password found
                            pbar.update(1)
                            return pwd

                        pbar.update(1)

        return None

    elif min_length > 0 and max_length > 0:
        total_combinations = sum(len(characters) ** length for length in range(min_length, max_length + 1))
        print(f'[*] Target Hash:{hash}\n[*] Hash Type:{hash_type}\n[*] Character Set:{characters}\n[*] Total Passwords:{total_combinations}')

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            with tqdm(total=total_combinations, desc='Generating and cracking hash') as pbar:
                for pwd in hsgenerate_passwords(min_length, max_length, characters):
                    future = executor.submit(check_hash, hash_fn, pwd, hash)
                    futures.append(future)
                    pbar.update(1)
                    if future.result():
                        return pwd

    return None


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    pdf_cracker = subparsers.add_parser("pdfcracker")
    pdf_cracker.add_argument('pdf_file', help='Path to the password-protected PDF file')
    pdf_cracker.add_argument('--wordlist', help='Path to the password list file', default=None)
    pdf_cracker.add_argument('--generate', action='store_true', help='Generate passwords on the fly')
    pdf_cracker.add_argument('--min_length', type=int, help='Minimum Length', default=1)
    pdf_cracker.add_argument('--max_length', type=int, help='Maximum Length', default=3)
    pdf_cracker.add_argument('--charset', type=str, help='Character set for the wordlist', default=(string.ascii_letters + string.digits + string.punctuation))
    pdf_cracker.add_argument('--max_workers', type=int, default=4)

    wl_parser = subparsers.add_parser("wordlistgen")
    wl_parser.add_argument('--min_length', type=int, default=1)
    wl_parser.add_argument('--max_length', type=int, default=3)
    wl_parser.add_argument('--charset', type=str, default=(string.ascii_letters + string.digits + string.punctuation + string.printable))
    wl_parser.add_argument('--output', type=str, required=True)

    hash_parser = subparsers.add_parser("hashcrack")
    hash_parser.add_argument('hash', help='The hash to crack.')
    hash_parser.add_argument('-w', '--wordlist', help='The path to the wordlist.')
    hash_parser.add_argument('--hash_type', type=str, help='The hash to use', default='md5')
    hash_parser.add_argument('--min_length', type=int, help='The minimum length of password to generate.')
    hash_parser.add_argument('--max_length', type=int, help='The maximum length of password to generate.')
    hash_parser.add_argument('-c', '--characters', help='The characters to use for password generation.')
    hash_parser.add_argument('--max_workers', type=int, help='The maximum number of threads.')


    args = parser.parse_args()

    if args.command == "wordlistgen":
        # Make custom wordlist and exit
        count = custom_wordlist(args.charset, args.min_length, args.max_length, args.output)
        print(f"Created {args.output} with {count} entries.")
        return
    if args.command == "hashcrack":
        cracked_password = crack_hash(args.hash, args.wordlist, args.hash_type, args.min_length, args.max_length,args.characters, args.max_workers)
        if cracked_password:
            print(f"[+] Found password: {cracked_password}")
        else:
            print("[!] Password not found.")
        exit()

    if args.generate and args.wordlist:
        print("Use either --generate or --wordlist, not both.")
        return

    if args.generate:
        total = count_generated_total(args.charset, args.min_length, args.max_length)
        pw_iter = generate_passwords(args.charset, args.min_length, args.max_length)
        found = crack_pdf_with_generator(args.pdf_file, pw_iter, total, args.max_workers)
    elif args.wordlist:
        with open(args.wordlist, 'r', errors='replace') as f:
            total = sum(1 for _ in f)
        found = crack_pdf_with_file(args.pdf_file, args.wordlist, args.max_workers)
    else:
        print("Either --wordlist must be provided or --generate must be specified.")
        return

    if found:
        print("[+] Password found:", found)
    else:
        print("[-] Password not found.")

if __name__ == "__main__":
    main()

