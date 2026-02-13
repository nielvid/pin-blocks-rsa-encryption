# ISO 9564-1 Format 0 PIN Block Tool

A secure, full-stack application for generating and visualizing ISO-0 PIN Blocks using RSA-OAEP and Triple DES encryption.

![ISO-0](https://m.media-amazon.com/images/I/41DWA+bF7-L.png)

## Overview
This tool allows financial developers to simulate the creation of an ISO 9564-1 Format 0 PIN Block. It demonstrates a secure architecture where the Zone PIN Key (ZPK) is never exposed to the client.

**Key Features:**
- **Secure PIN Entry**: PINs and PANs are encrypted on the client using **RSA-OAEP (SHA-256)** before transmission.
- **Server-Side ZPK**: The Triple DES Zone PIN Key is stored securely on the backend.
- **ISO-0 Logic**: Implements standard XOR logic between the PIN Field and PAN Field.
- **Visual Feedback**: Displays intermediate fields (PIN Field, PAN Field, Clear Block) and the final Encrypted PIN Block.

## Technology Stack
- **Frontend**: React (Vite), Web Crypto API (Native Browser Security)
- **Backend**: Node.js, Express, `crypto` module (OpenSSL)
- **Encryption**:
  - **Transport**: RSA-2048 with OAEP-SHA256 padding.
  - **PIN Block**: Triple DES (3DES/TDES) in ECB mode (implied by PIN Block standards, often handled via variants).

## Security Architecture

1.  **Handshake**: On startup, the Client requests a **Public Key** from the Server (`GET /api/public-key`).
2.  **Encryption**: The Client encrypts the `{ pin, pan }` payload using the Public Key via the **Web Crypto API**.
    - Algorithm: `RSA-OAEP`
    - Hash: `SHA-256`
3.  **Transmission**: The encrypted binary blob is Base64 encoded and sent to `POST /api/encrypt`.
4.  **Decryption**: The Server decrypts the payload using its **Private Key**.
5.  **processing**: The Server constructs the Clear PIN Block and encrypts it using the stored **ZPK** (Triple DES).
6.  **Response**: The Server returns the final Encrypted PIN Block and intermediate steps for educational visualization.

## Setup & Installation

### Prerequisites
- Node.js (v16+)
- npm

### Installation

1.  **Clone the repository**
    ```bash
    git clone <repository_url>
    cd pin-block-project
    ```

2.  **Install Backend Dependencies**
    ```bash
    cd server
    npm install
    ```

3.  **Install Frontend Dependencies**
    ```bash
    cd ../client
    npm install
    ```

## Usage

1.  **Start the Backend Server**
    ```bash
    # In /server directory
    node index.js
    ```
    Runs on `http://localhost:3001`.

2.  **Start the Frontend Client**
    ```bash
    # In /client directory
    npm run dev
    ```
    Runs on `http://localhost:5173` (typically).

3.  **Generate a PIN Block**
    - Open the frontend in your browser.
    - Enter a PIN (4-12 digits).
    - Enter a PAN (at least 13 digits).
    - Click **Generate Encrypted Block**.
    - Review the generated fields.

4.  **Verify Decryption**
    - Click the **Verify Decryption** button to send the Encrypted Block back to the server and recover the PIN.

## API Endpoints

### `GET /api/public-key`
Returns the server's RSA Public Key in SPKI (PEM) format.

### `POST /api/encrypt`
Accepts an RSA-encrypted payload containing PIN and PAN. Returns ISO-0 fields.
- **Body**: `{ "encryptedData": "Base64String" }`

### `POST /api/decrypt`
Decrypts an Encrypted PIN Block using the server's ZPK.
- **Body**: `{ "encryptedBlockHex": "...", "pan": "..." }`

## License
MIT
