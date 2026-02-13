import React, { useState, useEffect } from 'react';

// Helper to convert PEM string to ArrayBuffer
function pemToArrayBuffer(pem) {
  const b64Lines = pem.replace(/-----(BEGIN|END)( RSA)? PUBLIC KEY-----/g, "").replace(/\s/g, "");
  const str = window.atob(b64Lines);
  const buf = new ArrayBuffer(str.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    view[i] = str.charCodeAt(i);
  }
  return buf;
}

// Helper to array buffer to Base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function App() {
  const [inputs, setInputs] = useState({
    pin: '1234',
    pan: '4012345678901234'
    // ZPK (key) is now handled server-side only
  });
  const [publicCryptoKey, setPublicCryptoKey] = useState(null);
  const [result, setResult] = useState(null);
  const [decrypted, setDecrypted] = useState(null);
  const [error, setError] = useState(null);
  const [showPin, setShowPin] = useState(false);

  useEffect(() => {
    async function loadKey() {
      try {
        const res = await fetch('http://localhost:3001/api/public-key');
        const data = await res.json();

        // Import Key using Web Crypto API (RSA-OAEP)
        const binaryKey = pemToArrayBuffer(data.publicKey);
        const key = await window.crypto.subtle.importKey(
          "spki",
          binaryKey,
          {
            name: "RSA-OAEP",
            hash: "SHA-256"
          },
          true,
          ["encrypt"]
        );
        setPublicCryptoKey(key);
      } catch (err) {
        console.error(err);
        setError("Failed to load Public Key. Ensure Backend sends SPKI format or we parse PKCS1 correctly.");
      }
    }
    loadKey();
  }, []);

  const handleEncrypt = async () => {
    setError(null);
    setResult(null);
    setDecrypted(null);

    if (!publicCryptoKey) {
      setError("Public Key not loaded yet.");
      return;
    }

    try {
      const payload = JSON.stringify({ pin: inputs.pin, pan: inputs.pan });
      const enc = new TextEncoder();
      const encodedPayload = enc.encode(payload);

      const encryptedDataBuffer = await window.crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        publicCryptoKey,
        encodedPayload
      );

      const encryptedBase64 = arrayBufferToBase64(encryptedDataBuffer);

      const res = await fetch('http://localhost:3001/api/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ encryptedData: encryptedBase64 }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Encryption failed');
      setResult(data);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDecrypt = async () => {
    setError(null);
    setDecrypted(null);
    if (!result || !result.encryptedBlock) return;

    try {
      const res = await fetch('http://localhost:3001/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          encryptedBlockHex: result.encryptedBlock,
          pan: inputs.pan,
          // keyHex is no longer sent from client
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Decryption failed');
      setDecrypted(data);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div style={{ fontFamily: "'Inter', sans-serif", width: '100%', maxWidth: '480px', padding: '20px', color: '#333' }}>
      <div style={{ textAlign: 'center', marginBottom: '40px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '10px' }}>ISO 9564-1 PIN Tool</h1>
        <p style={{ color: '#666', fontSize: '14px' }}>Secure Format 0 Block Generator</p>
      </div>

      <div style={{ background: '#fff', padding: '30px', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)', border: '1px solid #eee' }}>

        <div style={{ marginBottom: '20px' }}>
          <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px', color: '#374151' }}>PIN</label>
          <div style={{ position: 'relative' }}>
            <input
              value={inputs.pin}
              onChange={e => setInputs({ ...inputs, pin: e.target.value })}
              placeholder="1234"
              type={showPin ? "text" : "password"}
              maxLength={12}
              style={{ width: '100%', padding: '10px 40px 10px 12px', fontSize: '16px', border: '1px solid #d1d5db', borderRadius: '6px', outline: 'none', transition: 'border-color 0.15s ease-in-out', boxSizing: 'border-box' }}
            />
            <button
              onClick={() => setShowPin(!showPin)}
              style={{ position: 'absolute', right: '10px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#6b7280', padding: 0, display: 'flex', alignItems: 'center' }}
              title={showPin ? "Hide PIN" : "Show PIN"}
            >
              {showPin ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              )}
            </button>
          </div>
          <small style={{ color: '#9ca3af', fontSize: '12px', marginTop: '4px', display: 'block' }}>4-12 digits</small>
        </div>

        <div style={{ marginBottom: '24px' }}>
          <label style={{ display: 'block', fontSize: '14px', fontWeight: '500', marginBottom: '8px', color: '#374151' }}>PAN</label>
          <input
            value={inputs.pan}
            onChange={e => setInputs({ ...inputs, pan: e.target.value })}
            placeholder="4012345678901234"
            maxLength={19}
            style={{ width: '100%', padding: '10px 12px', fontSize: '16px', border: '1px solid #d1d5db', borderRadius: '6px', outline: 'none', boxSizing: 'border-box' }}
          />
          <small style={{ color: '#9ca3af', fontSize: '12px', marginTop: '4px', display: 'block' }}>13-19 digits (Last digit is check digit)</small>
        </div>

        <button
          onClick={handleEncrypt}
          disabled={!publicCryptoKey}
          style={{
            width: '100%',
            padding: '12px',
            background: publicCryptoKey ? '#2563eb' : '#9ca3af',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: publicCryptoKey ? 'pointer' : 'not-allowed',
            fontSize: '15px',
            fontWeight: '600',
            transition: 'background-color 0.2s'
          }}
        >
          {publicCryptoKey ? 'Generate Encrypted Block' : 'Establishing Secure Connection...'}
        </button>
      </div>

      {error && (
        <div style={{ marginTop: '20px', padding: '12px 16px', background: '#fef2f2', color: '#b91c1c', borderRadius: '6px', border: '1px solid #fecaca', fontSize: '14px' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: '30px', background: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px', overflow: 'hidden' }}>
          <div style={{ background: '#f9fafb', padding: '12px 20px', borderBottom: '1px solid #e5e7eb' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '600', color: '#111827' }}>Output</h3>
          </div>
          <div style={{ padding: '20px' }}>
            <div style={{ display: 'grid', gap: '16px', marginBottom: '24px' }}>
              <div>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#6b7280', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Encrypted PIN Block</span>
                <div style={{ background: '#f3f4f6', padding: '12px', marginTop: '6px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '15px', color: '#1f2937', border: '1px solid #e5e7eb', wordBreak: 'break-all' }}>
                  {result.encryptedBlock}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div>
                  <span style={{ fontSize: '12px', fontWeight: '600', color: '#9ca3af', textTransform: 'uppercase' }}>PIN Field</span>
                  <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#4b5563', marginTop: '4px' }}>{result.pinField}</div>
                </div>
                <div>
                  <span style={{ fontSize: '12px', fontWeight: '600', color: '#9ca3af', textTransform: 'uppercase' }}>PAN Field</span>
                  <div style={{ fontFamily: 'monospace', fontSize: '13px', color: '#4b5563', marginTop: '4px' }}>{result.panField}</div>
                </div>
              </div>
            </div>

            <button
              onClick={handleDecrypt}
              style={{
                width: '100%',
                padding: '10px',
                background: '#fff',
                color: '#10b981',
                border: '1px solid #10b981',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500'
              }}
            >
              Verify Decryption
            </button>

            {decrypted && (
              <div style={{ marginTop: '16px', padding: '12px', background: '#ecfdf5', borderRadius: '6px', border: '1px solid #d1fae5', textAlign: 'center' }}>
                <span style={{ color: '#047857', fontSize: '14px' }}>Decrypted PIN: </span>
                <span style={{ fontWeight: '700', color: '#065f46', fontSize: '16px' }}>{decrypted.extractedPin}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
