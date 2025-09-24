## CRYPTO_PROTOKOL
## Author: Vuong Van Duy
## Email: vanduycn2@gmail.com
## Version: 1.0.0
## Instructions for using the Crypto module, for example the des module:
### Run the following command in the command line in the current project directory:
usage: exe.py [-h] --file FILE --key KEY [--iv IV] [--mode {ECB,CBC}] [--encrypt] [--output OUTPUT]

DES (ECB/CBC) encryption/decryption using command-line file paths. [DES (ECB/CBC) шифрование/расшифровка с использованием путей к файлам в командной строке.]

### options:
  -h, --help            --> show this help message and exit

  --file, -f FILE       --> Input file path: plaintext (for encryption) or HEX ciphertext (for decryption). [Путь к входному файлу: обычный текст (для шифрования) или
                        HEX-шифртекст (для расшифровки).]

  --key, -k KEY         --> Key file path (16 hex characters = 8 bytes). [Путь к файлу ключа (16 шестнадцатеричных символов = 8 байт).]

  --iv, -i IV           --> IV file path (16 hex characters = 8 bytes). Required for CBC mode. [Путь к файлу IV (16 шестнадцатеричных символов = 8 байт). Обязательно
                        для режима CBC.]

  --mode, -m {ECB,CBC}  --> DES mode (default: ECB). Options: ECB or CBC. [Режим DES (по умолчанию: ECB). Варианты: ECB или CBC.]

  --encrypt, -e         --> Enable to ENCRYPT. If omitted, the program will DECRYPT. [Включите для ШИФРОВАНИЯ. Если не указано, программа будет РАСШИФРОВЫВАТЬ.]

  --output, -o OUTPUT   --> Output file path. Encryption: saves HEX ciphertext. Decryption: saves UTF-8 plaintext. If omitted, result is printed. [Путь к выходному
                        файлу. Шифрование: сохраняет HEX-шифртекст. Расшифровка: сохраняет UTF-8 текст. Если не указано, результат печатается на экран.]
  