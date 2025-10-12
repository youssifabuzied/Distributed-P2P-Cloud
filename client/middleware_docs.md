# Middleware Documentation

## Overview

The **Middleware** component acts as a processing server in the Cloud P2P Controlled Image Sharing Project. It receives encryption and decryption requests from clients, processes them, and returns responses asynchronously.

## Architecture

```
                    ┌────────────────────────────────┐
                    │       MIDDLEWARE              │
                    │                               │
                    │  ┌─────────────────────────┐  │
                    │  │   TCP Listener          │  │
                    │  │   (Port 9000)           │  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │             ▼                  │
                    │  ┌─────────────────────────┐  │
                    │  │  Connection Handler     │  │
                    │  │  (Thread Pool)          │  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │             ▼                  │
                    │  ┌─────────────────────────┐  │
                    │  │  Request Processor      │  │
                    │  │  - Parse JSON           │  │
                    │  │  - Route to handler     │  │
                    │  │  - Build response       │  │
                    │  └──────────┬──────────────┘  │
                    │             │                  │
                    │             ▼                  │
                    │  ┌─────────────────────────┐  │
                    │  │  Business Logic         │  │
                    │  │  - encrypt_image()      │  │
                    │  │  - decrypt_image()      │  │
                    │  └─────────────────────────┘  │
                    │                               │
                    └───────────────────────────────┘
                                 ▲
                                 │ TCP
                                 │
                    ┌────────────┴──────────────┐
                    │        CLIENTS            │
                    └───────────────────────────┘
```

## File Structure

```
middleware.rs
├── Data Structures
│   ├── ClientRequest
│   └── MiddlewareResponse
├── Middleware Implementation
│   └── ClientMiddleware
├── Request Handlers
│   ├── handle_client_request()
│   ├── process_request()
│   ├── encrypt_image()
│   └── decrypt_image()
└── Main Entry Point
    └── main()
```

## Data Structures

### `ClientRequest`

Enum representing incoming requests from clients.

```rust
pub enum ClientRequest {
    EncryptImage { 
        request_id: u64,
        image_path: String 
    },
    DecryptImage { 
        request_id: u64,
        image_path: String 
    },
}
```

**Variants:**

#### `EncryptImage`
Request to encrypt an image file.

**Fields:**
- `request_id`: Unique identifier for tracking (provided by client)
- `image_path`: File system path to the image

**Example JSON:**
```json
{
  "EncryptImage": {
    "request_id": 1,
    "image_path": "/home/user/photo.jpg"
  }
}
```

#### `DecryptImage`
Request to decrypt an encrypted image file.

**Fields:**
- `request_id`: Unique identifier for tracking
- `image_path`: Path to the encrypted image

**Example JSON:**
```json
{
  "DecryptImage": {
    "request_id": 2,
    "image_path": "/home/user/photo.jpg.encrypted"
  }
}
```

---

### `MiddlewareResponse`

Response structure sent back to clients.

```rust
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
}
```

**Fields:**
- `request_id`: Matches the incoming request ID
- `status`: `"OK"` for success, `"ERROR"` for failure
- `message`: Human-readable description
- `output_path`: Path to output file (on success)

**Example Success Response:**
```json
{
  "request_id": 1,
  "status": "OK",
  "message": "Image encrypted successfully",
  "output_path": "/home/user/photo.jpg.encrypted"
}
```

**Example Error Response:**
```json
{
  "request_id": 1,
  "status": "ERROR",
  "message": "Image file not found",
  "output_path": null
}
```

#### Helper Methods

##### `success(request_id: u64, message: &str, output_path: Option<String>) -> Self`

Creates a success response.

**Parameters:**
- `request_id`: Request identifier
- `message`: Success message
- `output_path`: Path to output file

**Example:**
```rust
let response = MiddlewareResponse::success(
    1,
    "Image encrypted successfully",
    Some("/path/to/output.encrypted".to_string())
);
```

##### `error(request_id: u64, message: &str) -> Self`

Creates an error response.

**Parameters:**
- `request_id`: Request identifier
- `message`: Error description

**Example:**
```rust
let response = MiddlewareResponse::error(1, "File not found");
```

## Components

### `ClientMiddleware`

Main middleware server component.

```rust
pub struct ClientMiddleware {
    pub ip: String,
    pub port: u16,
}
```

**Fields:**
- `ip`: IP address to bind to (e.g., `"127.0.0.1"`)
- `port`: TCP port to listen on (default: `9000`)

---

#### Constructor

##### `new(ip: &str, port: u16) -> Self`

Creates a new middleware instance.

**Parameters:**
- `ip`: IP address to bind to
- `port`: TCP port number

**Example:**
```rust
let middleware = ClientMiddleware::new("127.0.0.1", 9000);
```

**Binding Options:**
- `"127.0.0.1"` - Localhost only (secure, local testing)
- `"0.0.0.0"` - All interfaces (network accessible)
- Specific IP - Bind to particular interface

---

#### Public Methods

##### `start(&self) -> Result<(), Box<dyn Error>>`

Starts the middleware server and listens for connections.

**Behavior:**
1. Binds TCP listener to configured address
2. Enters infinite loop accepting connections
3. Spawns new thread for each client connection
4. Never returns (runs until process killed)

**Returns:**
- `Ok(())`: Never returns normally
- `Err(...)`: Binding failed or fatal error

**Example:**
```rust
let middleware = ClientMiddleware::new("127.0.0.1", 9000);
middleware.start()?;  // Blocks forever
```

**Console Output:**
```
========================================
Cloud P2P Client Middleware (Async)
========================================
[Middleware] Listening on 127.0.0.1:9000
[Middleware] Ready to process async requests...

[Middleware] New connection from: 127.0.0.1:54321
[Middleware] Received: {"EncryptImage":{...}}
[Middleware] Processing request #1: EncryptImage { ... }
[Middleware] [Req #1] Encrypting: photo.jpg
[Middleware] [Req #1] Encryption complete: photo.jpg.encrypted
[Middleware] Sent response for request #1
```

---

#### Internal Methods

##### `handle_client_request(stream: TcpStream) -> Result<(), Box<dyn Error>>`

**Internal:** Handles a single client connection in a dedicated thread.

**Parameters:**
- `stream`: TCP connection to client

**Returns:** `Result<(), Box<dyn Error>>`

**Process Flow:**
1. Create buffered reader and writer from stream
2. Read one line (JSON request + `\n`)
3. Parse JSON into `ClientRequest`
4. Call `process_request()` to handle it
5. Serialize response to JSON
6. Write response + `\n` to stream
7. Close connection

**Error Handling:**
- Empty lines: Ignored
- Invalid JSON: Returns error response
- I/O errors: Logged and connection closed

**Thread Model:**
```
Main Thread (Listener)
    ├─▶ Worker Thread 1 (Client A)
    ├─▶ Worker Thread 2 (Client B)
    └─▶ Worker Thread 3 (Client C)
```

---

##### `process_request(request: ClientRequest) -> MiddlewareResponse`

**Internal:** Routes requests to appropriate handlers.

**Parameters:**
- `request`: Parsed client request

**Returns:** `MiddlewareResponse`

**Routing Logic:**
```rust
match request {
    ClientRequest::EncryptImage { request_id, image_path } => {
        encrypt_image(request_id, &image_path)
    }
    ClientRequest::DecryptImage { request_id, image_path } => {
        decrypt_image(request_id, &image_path)
    }
}
```

---

##### `encrypt_image(request_id: u64, image_path: &str) -> MiddlewareResponse`

**Internal:** Handles image encryption requests.

**Parameters:**
- `request_id`: Request identifier
- `image_path`: Path to image file

**Returns:** `MiddlewareResponse`

**Current Implementation (Dummy):**
1. Validates file exists
2. Simulates processing (500ms sleep)
3. Generates output path: `{input}.encrypted`
4. Returns success response

**⚠️ Note:** Currently a placeholder! Does not actually encrypt files.

**Production Implementation Would:**
1. Read image file from disk
2. Apply encryption algorithm (AES-256, etc.)
3. Write encrypted data to output file
4. Return actual output path

**Example:**
```rust
// Request
encrypt_image(1, "/home/user/photo.jpg")

// Response
MiddlewareResponse {
    request_id: 1,
    status: "OK",
    message: Some("Image encrypted successfully"),
    output_path: Some("/home/user/photo.jpg.encrypted")
}
```

---

##### `decrypt_image(request_id: u64, image_path: &str) -> MiddlewareResponse`

**Internal:** Handles image decryption requests.

**Parameters:**
- `request_id`: Request identifier
- `image_path`: Path to encrypted image file

**Returns:** `MiddlewareResponse`

**Current Implementation (Dummy):**
1. Validates file exists
2. Simulates processing (500ms sleep)
3. Generates output path:
   - If ends with `.encrypted`: strips suffix
   - Otherwise: appends `.decrypted`
4. Returns success response

**⚠️ Note:** Currently a placeholder! Does not actually decrypt files.

**Output Path Logic:**
```rust
// Input: "photo.jpg.encrypted" → Output: "photo.jpg"
// Input: "image.png"          → Output: "image.png.decrypted"
```

**Example:**
```rust
// Request
decrypt_image(2, "/home/user/photo.jpg.encrypted")

// Response
MiddlewareResponse {
    request_id: 2,
    status: "OK",
    message: Some("Image decrypted successfully"),
    output_path: Some("/home/user/photo.jpg")
}
```

## Communication Protocol

### TCP Protocol

**Format:** Line-delimited JSON over TCP

**Request:**
```
JSON_REQUEST\n
```

**Response:**
```
JSON_RESPONSE\n
```

**Delimiter:** Newline character (`\n`) separates messages

---

### Request-Response Cycle

```
CLIENT                           MIDDLEWARE
   │                                  │
   │──── TCP Connect ───────────────▶│
   │                                  │
   │──── JSON Request + \n ─────────▶│
   │                                  │ Parse JSON
   │                                  │ Process request
   │                                  │ Build response
   │                                  │
   │◀─── JSON Response + \n ─────────│
   │                                  │
   │──── TCP Close ──────────────────│
   │                                  │
```

---

### Message Examples

**Encryption Request:**
```json
{"EncryptImage":{"request_id":1,"image_path":"photo.jpg"}}\n
```

**Encryption Response:**
```json
{"request_id":1,"status":"OK","message":"Image encrypted successfully","output_path":"photo.jpg.encrypted"}\n
```

**Decryption Request:**
```json
{"DecryptImage":{"request_id":2,"image_path":"photo.jpg.encrypted"}}\n
```

**Error Response:**
```json
{"request_id":2,"status":"ERROR","message":"Image file not found","output_path":null}\n
```

## Threading Model

### Connection Handling

Each client connection is handled in a separate thread:

```rust
for stream in listener.incoming() {
    thread::spawn(move || {
        handle_client_request(stream)
    });
}
```

**Characteristics:**
- ✅ **Concurrent:** Multiple clients handled simultaneously
- ✅ **Isolated:** Each connection independent
- ✅