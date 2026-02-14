const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());


// --- Security Configuration ---
// Hardcoded ZPK for demonstration (in production, use KMS or secure env vars)
// AES-256 Key (32 bytes = 64 hex chars)
const SERVER_ZPK_HEX = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'; 

// Generate RSA Key Pair for shielding sensitive data (PIN/PAN) in transit from client
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
// -----------------------------

/**
 * ISO-0 PIN Block Logic
 */
function getIso0Fields(pin, pan) {
    const pinLen = pin.length;
    const pinField = "0" + pinLen.toString(16).toUpperCase() + pin + "F".repeat(14 - pinLen);
    
    const panBody = pan.slice(pan.length - 13, pan.length - 1);
    const panField = "0000" + panBody;
    
    const bufPin = Buffer.from(pinField, 'hex');
    const bufPan = Buffer.from(panField, 'hex');
    const clearBlock = Buffer.alloc(8);
    
    for (let i = 0; i < 8; i++) {
        clearBlock[i] = bufPin[i] ^ bufPan[i];
    }
    
    return { pinField, panField, clearBlock };
}

// Endpoint to provide public key to client
app.get('/api/public-key', (req, res) => {
    res.json({ publicKey: publicKeyPem });
});

app.post('/api/encrypt', (req, res) => {
    try {
        const { encryptedData } = req.body;
        
        if (!encryptedData) {
            return res.status(400).json({ error: "Missing encryptedData" });
        }

        // 1. Decrypt payload using server's Private Key
        // CHANGED: Using OAEP PADDING (SHA-256) to fix Node.js security error with PKCS1
        const decryptedBuffer = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(encryptedData, 'base64')
        );

        const { pin, pan } = JSON.parse(decryptedBuffer.toString());

        if (!pin || !pan) {
            return res.status(400).json({ error: "Invalid payload: missing pin or pan" });
        }

        // 2. Encrypt PIN Block using Server-side ZPK (AES-256)
        const { pinField, panField, clearBlock } = getIso0Fields(pin, pan);
        
        const key = Buffer.from(SERVER_ZPK_HEX, 'hex');
        const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
        // AES block size is 16 bytes. ISO-0 block is 8 bytes.
        // We use default padding (PKCS#7) which usually adds bytes to reach 16 bytes.
        // cipher.setAutoPadding(true); // Default is true
        
        const encryptedBlock = Buffer.concat([cipher.update(clearBlock), cipher.final()]);
        
        res.json({
            pinField, // Ideally shouldn't return this in prod, but keeping for tool visualization
            panField,
            clearBlock: clearBlock.toString('hex').toUpperCase(), // Ideally shouldn't return this in prod
            encryptedBlock: encryptedBlock.toString('hex').toUpperCase()
        });
    } catch (err) {
        console.error("Encrypt Error:", err);
        res.status(400).json({ error: "Decryption or processing failed. Ensure Client uses OAEP-SHA256." });
    }
});

app.post('/api/decrypt', (req, res) => {
    try {
        const { encryptedBlockHex, pan } = req.body;
        
        const key = Buffer.from(SERVER_ZPK_HEX, 'hex');
        
        if (!encryptedBlockHex || !pan) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const panBody = pan.slice(pan.length - 13, pan.length - 1);
        const panField = "0000" + panBody;
        const bufPan = Buffer.from(panField, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
        // decipher.setAutoPadding(true); // Default is true
        
        const encryptedBuf = Buffer.from(encryptedBlockHex, 'hex');
        const decryptedBlock = Buffer.concat([decipher.update(encryptedBuf), decipher.final()]);

        const pinFieldBuf = Buffer.alloc(8);
        for (let i = 0; i < 8; i++) {
            pinFieldBuf[i] = decryptedBlock[i] ^ bufPan[i];
        }

        const pinFieldHex = pinFieldBuf.toString('hex').toUpperCase();
        const pinLen = parseInt(pinFieldHex[1], 16);
        const pin = pinFieldHex.substring(2, 2 + pinLen);

        res.json({ pinField: pinFieldHex, extractedPin: pin });
    } catch (err) {
        console.error("Decrypt Error:", err);
        res.status(400).json({ error: err.message });
    }
});

// Serve Static Frontend Assets
app.use(express.static(path.join(__dirname, '../client/dist')));

// Handle SPA routing - return index.html for any unknown routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/dist', 'index.html'));
});

const PORT = 3001;
app.listen(PORT, () => {
    console.log(`Backend running on port ${PORT}`);
});
