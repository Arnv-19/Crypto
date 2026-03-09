# Lab 7: Diffie-Hellman Key Exchange & Encryption 

> [!NOTE]
> This document provides the mathematical foundation, the implementation breakdown, and a clear step-by-step Viva Demonstration script for the Diffie-Hellman key exchange (in C).

## The Concept (What is happening and why?)

Diffie-Hellman (DH) is a method for two parties (Client and Server) to establish a **shared secret key** over an insecure channel without ever transmitting the secret key over the network. They only transmit "Public Keys."

### The Mathematical Steps:
1. **Public Parameters:** Both agree on a large Prime number (`P`) and a Generator base (`G`). In our lab, we use `P = 23` and `G = 9` for simplicity.
2. **Private Keys:**
   - **Server** chooses a random Private Key (`a`). Let's say `a = 5`.
   - **Client** chooses a random Private Key (`b`). Let's say `b = 11`.
   - *These remain secret!*
3. **Public Keys:**
   - **Server** calculates its Public Key `A = (G^a) mod P`.
   - **Client** calculates its Public Key `B = (G^b) mod P`.
4. **Exchange:** Server sends `A` to Client. Client sends `B` to Server.
5. **Shared Secret Calculation:**
   - **Server** calculates the shared secret: `Secret = (B^a) mod P`.
   - **Client** calculates the shared secret: `Secret = (A^b) mod P`.
   - *Due to the properties of modular exponentiation, both will derive the **exact same number!***
6. **Encryption/Decryption:**
   - Once the shared secret is established, it is used as a symmetric key. 
   - In this implementation, the **client** uses a simple **XOR Cipher** to encrypt a typed message (`Message ^ Secret`) and sends it.
   - The **server** receives the data and uses the exact same shared secret to reverse the XOR cipher (`EncryptedMessage ^ Secret = Message`).

---

## The Code Structure (How it was built)

1. **[dh.h](file:///c:/Users/Arnav/Coding/Crypto/Lab7/dh.h)**: Contains the core mathematical function [power(base, exp, mod)](file:///c:/Users/Arnav/Coding/Crypto/Lab7/dh.h#6-20) which computes [(base^exp) % mod](file:///c:/Users/Arnav/Coding/Crypto/Lab7/mallory.c#17-147) efficiently to avoid integer overflow. It also contains the [encrypt_decrypt()](file:///c:/Users/Arnav/Coding/Crypto/Lab7/dh.h#21-29) XOR cipher.
2. **[server.c](file:///c:/Users/Arnav/Coding/Crypto/Lab5/server.c)**: Connects via winsock on Port `8080`. Generates its private/public key, sends its public key, receives the client's public key, computes the secret. It then waits to receive the encrypted string from the client and decrypts it.
3. **[client.c](file:///c:/Users/Arnav/Coding/Crypto/Lab7/client.c)**: Connects to the server. Generates its private/public key, exchanges public keys, computes the secret. **It then prompts the user to type a message**, encrypts it, and sends it to the server.

---

## Viva Demo Plan (Step-by-Step Script)

Follow these steps to demonstrate the Diffie-Hellman Key Exchange perfectly.

### Step 1: Compile the Code
Open two Command Prompt or PowerShell windows in your `Lab7` directory:

```powershell
gcc server.c -o server.exe -lws2_32
gcc client.c -o client.exe -lws2_32
```

### Step 2: Start the Server (The Sender)
In the first terminal, run the server. It will immediately generate its keys and wait for the client.
```powershell
.\server.exe
```
**Expected Output:**
```text
Server Diffie-Hellman Initialization:
  Prime (P): 23
  Generator (G): 9
  Server Private Key (a): 10
  Server Public Key (A): 18

Waiting for incoming connections...
```


### Step 3: Start the Client (The Sender)
In the second terminal, run the client. The key exchange will happen automatically, and then it will wait for you to type a message.
```powershell
.\client.exe
```

**What happens on the Client Side:**
```text
Client Diffie-Hellman Initialization:
  Prime (P): 23
  Generator (G): 9
  ... keys ...

--- Connected to server ---
Received Server Public Key (A): ...
Sent Client Public Key (B) to Server.
>> Calculated Shared Secret Key: ... <<

Enter a message to send to the server: Hello server this is a test!
Original Message: Hello server this is a test!
Encrypted Message: 4A 65 6C 6C 6F 20 ... 
Encrypted message sent to server.
```

**Expected Output on the Server Side (The Receiver):**
```text
--- Client Connected ---
Sent Server Public Key (A) to Client.
Received Client Public Key (B): ...
>> Calculated Shared Secret Key: ... <<

Received Encrypted Message:
4A 65 6C ...

Decrypted Message: Hello server this is a test!
```

> [!IMPORTANT]
> **What to highlight to the examiner:**
> 1. Show that **both terminals independently calculated the exact same Shared Secret Key.**
> 2. Highlight that the Private Keys were *never* sent over the network. Only Public keys were exchanged!
> 3. Show you **typing the message** on the client.
> 4. Show the Server receiving the gibberish Hex data and successfully decrypting it into English because it derived the correct shared key.

---

## ATTACK ADD-ON: Man-in-the-Middle and Replay Proxy

For the second part of the Viva, demonstrate the vulnerabilities inherent to basic Diffie-Hellman when there is no authentication.

### The MitM Concept (How Mallory Works)
Diffie-Hellman does not authenticate *who* you are talking to.
1. `mallory.exe` acts as a proxy. She opens Port `8080` (where Client connects) and connects to Port `8081` (where the real Server expects connections).
2. When Client sends Key `B`, Mallory intercepts it and sends back her own Fake Key. Client forms a shared secret with *Mallory*.
3. When Server sends Key `A`, Mallory intercepts it and sends back her own Fake Key. Server forms a shared secret with *Mallory*.
4. When Client sends an encrypted message, Mallory decrypts it, reads it, re-encrypts it with the Server's secret, and forwards it! Neither Client nor Server knows they are compromised.

### The Replay Attack Concept
Because there are no sequence numbers or timestamps in this protocol, an attacker (or a malicious client) can simply capture the encrypted bytes of a previous message and fire them at the server again. The server will decrypt and process it as a brand-new valid instruction.

### Viva Demo Plan: The Attacks
Open 3 Terminal Windows in your `Lab7` directory.

#### 1. Start the Server
In Terminal 1, run the server. (It now listens on 8081).
```powershell
.\server.exe
```

#### 2. Start Mallory (The Attacker)
In Terminal 2, run the MitM attacker.
```powershell
.\mallory.exe
```
**Output:** `[Mallory] Listening on port 8080 for Client...`

#### 3. Start the Client
In Terminal 3, run the client.
```powershell
.\client.exe
```

Look at the **Mallory** terminal! You will see her successfully intercepting the keys and forming entirely different shared secrets with both the client and the server.

#### 4. Demonstrate Interception
In the **Client** terminal, choose `Option 1` and type a secret message:
> `Enter a message to send to the server: My bank pin is 1234`

Look at the **Mallory** terminal again! You will see:
```text
[Mallory] Intercepted Encrypted Packet from Client!
[Mallory] DECRYPTED MESSAGE: "My bank pin is 1234"
[Mallory] Re-encrypted and forwarded packet to Server.
```
And the **Server** terminal will receive the message normally, oblivious to the fact that Mallory read it.

#### 5. Demonstrate the Replay Attack
Go back to the **Client** terminal. This time, choose `Option 2` (Execute Replay Attack).

The Client will blindly take the raw hex bytes from the previous packet and fire them at the Server.

Look at the **Server** terminal. You will see:
```text
Received Encrypted Message:
<Hex Bytes>
Decrypted Message: My bank pin is 1234
```
It processes the exact same command a second time! You can tell the examiner: *"Because without timestamps or nonces, the server cannot distinguish between a fresh message and an old packet injected by an attacker."*
