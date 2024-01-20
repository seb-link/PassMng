# Password Manager

A simple password manager script written in Python that uses SQLite for storing passwords and implements encryption using Argon2 for key derivation and AES for data encryption.

## Requirements
- Python 3.x
- `argon2-cffi` library (install using `pip install argon2-cffi`)
- `pycryptodome` library (install using `pip install pycryptodome`)
- `colorama` library (install using `pip install colorama`)
- `pyperclip` library (install using `pip install pyperclip`)

## Usage

1. Run the script:
   ```bash
   python main.py
   ```

2. You will be prompted with options:
   - `0` - Show commands.
   - `1` - Encrypt the password database (creates a new encrypted database or re-encrypts an existing one).
   - `2` - Decrypt the password database (requires the encryption key).
   - `3` - View current passwords in the database.
   - `4` - Add a new password entry to the database.
   - `5` - Select a password to copy with his index.
   - `6` - Search password by website.
   - `6` - Delete stored password.
   - `99` - Exit.

3. Follow the instructions for each option:
   - When encrypting or decrypting, you will be asked for a ciphering key. Make sure to remember it, as losing it can result in losing all stored passwords.
   - When adding a new password, you can generate a random password by entering "RANDOM" when prompted for the password.

## Security Warning
- **Losing the encryption key can result in the loss of all stored passwords. No Key No Data.**
- The script checks password entropy and issues a warning if the entropy is low, indicating a potential weak password.

## Issues
If you have any issue feel free to visite the [issue](https://github.com/seb-link/PassMng/issues) pages.


## License
This project is licensed under the [GNU General Public License v3.0](LICENSE).
