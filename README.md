# Browser Cookie Decryptor

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

## Execution Flow

1. **Terminate Edge Process**: 
   - The program begins by attempting to terminate the Edge browser process using the `KillProcessByName` function. This ensures that the SQLite database containing the cookies is not locked, allowing for read access.

2. **Retrieve Encrypted AES Key**:
   - The program then calls `getEncryptedAESKey` to retrieve the encrypted AES key from the Edge browser's `Local State` file. The key is base64-encoded, so it is decoded using `base64Decode`.

3. **Decrypt AES Key**:
   - Once the AES key is decoded, it is decrypted using the Windows DPAPI (`CryptUnprotectData`) through the `decryptAESKey` function. This decrypted AES key is then used to decrypt the cookies.

4. **Locate Edge Browser Cookie Database**:
   - The program constructs the path to the SQLite database that stores the cookies via the `getEdgeBrowserCookiePath` function.

5. **Decrypt Cookies**:
   - Using the decrypted AES key, the program reads and decrypts the cookies stored in the SQLite database. The `readAndDecryptCookies` function handles the decryption process, and the `decryptData` function determines the encryption method (AES-GCM or DPAPI) and decrypts the cookie values.

6. **Output to JSON**:
   - Finally, the decrypted cookies are written to a JSON file named `cookies.json` using the `writeCookiesToJson` function, providing a structured output of the cookies' names, values, domains, paths, creation times, and expiration times.


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

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgements

- [SQLite](https://www.sqlite.org/)
- [nlohmann/json](https://github.com/nlohmann/json)
- [Windows API](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
