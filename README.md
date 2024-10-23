# Edge Browser Cookie Decryptor

This project is designed to decrypt cookies stored by the Microsoft Edge browser. It retrieves the encrypted AES key from the `Local State` file, decrypts it using Windows DPAPI, and then uses the decrypted AES key to decrypt the cookies stored in the Edge browser's SQLite database.

## Features

- Terminate the Edge browser process to ensure the database is not locked.
- Retrieve and decrypt the AES key used by Edge to encrypt cookies.
- Read and decrypt cookies from the Edge browser's SQLite database.
- Export decrypted cookies to a JSON file.

## Prerequisites

- Windows operating system
- Microsoft Edge browser
- [SQLite3](https://www.sqlite.org/download.html)
- [nlohmann/json](https://github.com/nlohmann/json) library

## Building

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/edge-cookie-decryptor.git
    cd edge-cookie-decryptor
    ```

2. Open the project in your IDE (e.g., CLion).

3. Ensure you have the required libraries installed and linked:
    - `sqlite3`
    - `nlohmann/json`

4. Build the project using your IDE's build tools.

## Usage

1. Ensure the Edge browser is closed. The program will attempt to terminate the Edge process if it is running.

2. Run the executable:
    ```
    ./edge-cookie-decryptor.exe
    ```

3. The program will output the decrypted cookies to a file named `cookies.json`.

## Code Overview

### `main.cpp`

- **KillProcessByName**: Terminates the Edge browser process.
- **getUserProfilePath**: Retrieves the user's profile path.
- **getEdgeBrowserCookiePath**: Constructs the path to the Edge browser's cookie database.
- **getLocalStatePath**: Constructs the path to the Edge browser's `Local State` file.
- **getEncryptedAESKey**: Retrieves the encrypted AES key from the `Local State` file.
- **base64Decode**: Decodes a base64-encoded string.
- **decryptAESKey**: Decrypts the AES key using Windows DPAPI.
- **decryptWithAESGCM**: Decrypts data using AES-GCM.
- **decryptWithDPAPI**: Decrypts data using Windows DPAPI.
- **decryptData**: Determines the encryption method and decrypts the data.
- **writeCookiesToJson**: Writes the decrypted cookies to a JSON file.
- **readAndDecryptCookies**: Reads and decrypts cookies from the SQLite database.

### `shell.c`

- **fiddle_interrupt**: Interrupts the SQLite database operation.
- **fiddle_db_filename**: Retrieves the filename of the database.
- **fiddle_reset_db**: Resets the database.
- **fiddle_export_db**: Exports the database contents.
- **fiddle_exec**: Executes SQL commands.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgements

- [SQLite](https://www.sqlite.org/)
- [nlohmann/json](https://github.com/nlohmann/json)
- [Windows API](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
