# Multi-Purpose Cracking Tool

A fast, multi-feature security testing toolkit for PDFs, hashes, and custom wordlist generation.
This project is a multi-module password and hash-cracking tool built using Python. It includes support for PDF password cracking, hash cracking, and custom wordlist generation using flexible character sets and multi-threading.

The tool is designed for educational and ethical cybersecurity testing only. It demonstrates concepts such as brute-force generation, multithreading, hashing, and file-based batch processing.

## Features
#### PDF Password Cracker

-Supports dictionary-based cracking

-Supports on-the-fly password generation

-Handles large wordlists like rockyou.txt using batch processing

-Multi-threaded for improved speed

-Progress bar included with tqdm

### Hash Cracker

Supports common hash algorithms:

-MD5, SHA1, SHA224, SHA256, SHA384, SHA512

-SHA3 family

-Uses wordlist or generated passwords

-ThreadPoolExecutor for parallel attempts

-Clean progress display

### Custom Wordlist Generator

Create wordlists using:

-Letters

-Digits

-Symbols

-Any custom character set

-Adjustable min/max lengths

-Progress bar while writing large lists

## Installation
### 1.Clone the repository:
```bash
git clone https://github.com/darkend2202/Multi-Cracking-Tool.git
cd Multi-Cracking-Tool
```
### 2.Install dependencies: 
```bash
pip install -r requirements.txt
```
# Usage
### PDF Cracker
```bash
python cracker.py pdfcrack file.pdf --wordlist rockyou.txt
```
### PDF Cracker (generate passwords)
```bash
python cracker.py pdfcrack file.pdf --generate --charset abc123 --min_length 1 --max_length 4
```
### Wordlist Generator
```bash
python cracker.py wordlistgen --charset abc123 --min_length 1 --max_length 5 --output list.txt
```
### Hash Cracker
```bash
python cracker.py hashcrack <hash_value> -w wordlist.txt --hash_type sha256
```
### Hash Cracker (generate passwords)
```bash
python cracker.py hashcrack <hash_value> -c abc123 --min_length 2 --max_length 5 --hash_type sha256 
```
## Legal Disclaimer

This tool is intended ONLY for educational and authorized security testing.
Misuse for illegal activities is strictly prohibited. You are responsible for your actions.

## Contributing

Pull requests and improvements are welcome!
