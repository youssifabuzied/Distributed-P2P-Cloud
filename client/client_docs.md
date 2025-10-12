# Client Documentation

## Overview

The **Client** component is part of the Cloud P2P Controlled Image Sharing Project. It provides an asynchronous interface for users to submit image encryption and decryption requests to the middleware without blocking the UI.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    CLIENT                             │
│                                                       │
│  ┌─────────────┐     ┌──────────────┐               │
│  │     UI      │────▶│   Client     │               │
│  │  (CLI Loop) │     │   Instance   │               │
│  └─────────────┘     └──────┬───────┘               │
│                              │                        │
│                              ▼                        │
│                    ┌─────────────────┐               │
│                    │ RequestTracker  │               │
│                    │ (Thread-safe)   │               │
│                    └─────────────────┘               │
│                              │                        │
│                              ▼                        │
│                    ┌─────────────────┐               │
│                    │ Background      │               │
│                    │ Worker Threads  │               │
│                    └────────┬────────┘               │
│                             │                         │
└─────────────────────────────┼─────────────────────────┘
                              │
                              │ TCP Socket
                              ▼
                    ┌──────────────────┐
                    │   MIDDLEWARE     │
                    │   (Port 9000)    │
                    └──────────────────┘
```

## File Structure

```
client.rs
├── Data Structures
│   ├── ClientMetadata
│   ├── ClientRequest
│   ├── MiddlewareResponse
│   └── RequestStatus
├── Request Tracker
│   └── RequestTracker
├── Client Implementation
│   └── Client
└── Main Entry Point
    └── main()
```

## Data Structures

### `ClientMetadata`

Stores client identification information.

```rust
pub struct ClientMetadata {
    pub username: String,  // Client username
    pub ip: String,        // Client IP address
    pub port: u16,         // Client port (currently unused)
}
```

**Fields:**
- `username`: Identifies the client user
- `ip`: Client's IP address (for future P2P communication)
- `port`: Reserved for future peer-to-peer listening (currently 8080)

---

### `ClientRequest`

Enum representing requests sent to the middleware.

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
- **`EncryptImage`**: Request to encrypt an image file
  - `request_id`: Unique identifier for tracking
  - `image_path`: Absolute or relative path to the image file
  
- **`DecryptImage`**: Request to decrypt an image file
  - `request_id`: Unique identifier for tracking
  - `image_path`: Path to the encrypted image file

**Serialization:** JSON format over TCP
```json
{
  "EncryptImage": {
    "request_id": 1,
    "image_path": "/path/to/image.jpg"
  }
}
```

---

### `MiddlewareResponse`

Response structure received from middleware.

```rust
pub struct MiddlewareResponse {
    pub request_id: u64,
    pub status: String,
    pub message: Option<String>,
    pub output_path: Option<String>,
}
```

**Fields:**
- `request_id`: Matches the request ID for tracking
- `status`: Either `"OK"` or `"ERROR"`
- `message`: Human-readable status message
- `output_path`: Path to the output file (if successful)

**Example Response:**
```json
{
  "request_id": 1,
  "status": "OK",
  "message": "Image encrypted successfully",
  "output_path": "image.jpg.encrypted"
}
```

---

### `RequestStatus`

Tracks the lifecycle of a request.

```rust
pub enum RequestStatus {
    Pending,                            // Request created, not sent yet
    InProgress,                         // Request sent, waiting for response
    Completed(MiddlewareResponse),      // Request completed successfully
    Failed(String),                     // Request failed with error message
}
```

**State Transitions:**
```
Pending → InProgress → Completed
                    └→ Failed
```

## Components

### `RequestTracker`

Thread-safe tracking system for managing asynchronous requests.

```rust
pub struct RequestTracker {
    requests: Arc<Mutex<HashMap<u64, RequestStatus>>>,
    next_id: Arc<Mutex<u64>>,
}
```

**Methods:**

#### `new() -> Self`
Creates a new request tracker.

#### `create_request(&self) -> u64`
Generates a new unique request ID and initializes its status to `Pending`.

**Returns:** `u64` - The new request ID

#### `update_status(&self, id: u64, status: RequestStatus)`
Updates the status of a request.

**Parameters:**
- `id`: Request ID to update
- `status`: New status

#### `get_status(&self, id: u64) -> Option<RequestStatus>`
Retrieves the current status of a request.

**Returns:** `Option<RequestStatus>` - The status if found, `None` otherwise

#### `list_all(&self) -> Vec<(u64, RequestStatus)>`
Returns all requests and their statuses.

**Returns:** Vector of tuples `(request_id, status)`

#### `pending_count(&self) -> usize`
Counts requests that are pending or in progress.

**Returns:** Number of active requests

---

### `Client`

Main client interface for submitting and tracking requests.

```rust
pub struct Client {
    pub metadata: ClientMetadata,
    pub middleware_addr: String,
    pub tracker: RequestTracker,
}
```

**Fields:**
- `metadata`: Client identification information
- `middleware_addr`: Address of middleware (e.g., `"127.0.0.1:9000"`)
- `tracker`: Request tracking system

#### Constructor

##### `new(username: &str, ip: &str, port: u16, middleware_addr: &str) -> Self`

Creates a new client instance.

**Parameters:**
- `username`: Client username
- `ip`: Client IP address
- `port`: Client port (for future use)
- `middleware_addr`: Middleware TCP address

**Example:**
```rust
let client = Client::new("user1", "127.0.0.1", 8080, "127.0.0.1:9000");
```

---

#### Public Methods

##### `request_encryption(&self, image_path: &str) -> Result<u64, Box<dyn Error>>`

Submits an image encryption request asynchronously.

**Parameters:**
- `image_path`: Path to the image file

**Returns:**
- `Ok(u64)`: Request ID for tracking
- `Err(...)`: Error if file doesn't exist

**Behavior:**
1. Validates file exists
2. Creates request with unique ID
3. Spawns background thread to send request
4. Returns immediately with request ID

**Example:**
```rust
let request_id = client.request_encryption("photo.jpg")?;
println!("Request #{} queued", request_id);
```

---

##### `request_decryption(&self, image_path: &str) -> Result<u64, Box<dyn Error>>`

Submits an image decryption request asynchronously.

**Parameters:**
- `image_path`: Path to the encrypted image file

**Returns:**
- `Ok(u64)`: Request ID for tracking
- `Err(...)`: Error if file doesn't exist

**Example:**
```rust
let request_id = client.request_decryption("photo.jpg.encrypted")?;
```

---

##### `check_status(&self, request_id: u64)`

Displays the status of a specific request.

**Parameters:**
- `request_id`: The request ID to check

**Output:** Prints formatted status to console

**Example:**
```
Request #1: ✓ Completed
  Status: OK
  Message: Image encrypted successfully
  Output: photo.jpg.encrypted
```

---

##### `list_requests(&self)`

Displays all requests and their current statuses.

**Output:** Formatted table of all requests

**Example:**
```
========================================
Request History
========================================
#  1 | ✓ Completed - image1.jpg.encrypted
#  2 | 🔄 In Progress
#  3 | ⏳ Pending
========================================
Pending/In-Progress: 2
```

---

##### `start_ui(&self)`

Starts the interactive command-line interface.

**Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `encrypt <path>` | Queue encryption request | `encrypt photo.jpg` |
| `decrypt <path>` | Queue decryption request | `decrypt photo.jpg.encrypted` |
| `status <id>` | Check request status | `status 1` |
| `list` | List all requests | `list` |
| `pending` | Show pending count | `pending` |
| `exit` | Exit client | `exit` |

**Example Session:**
```
> encrypt image1.jpg
✓ Request #1 queued (background processing)

> encrypt image2.jpg
✓ Request #2 queued (background processing)

> list
========================================
Request History
========================================
#  1 | 🔄 In Progress
#  2 | ⏳ Pending
========================================
Pending/In-Progress: 2

> status 1
Request #1: ✓ Completed
  Status: OK
  Message: Image encrypted successfully
  Output: image1.jpg.encrypted

> exit
Goodbye!
```

---

#### Internal Methods

##### `send_request_async(&self, request: ClientRequest) -> u64`

**Internal:** Spawns a background thread to send the request.

**Parameters:**
- `request`: The request to send

**Returns:** Request ID

**Behavior:**
1. Updates status to `InProgress`
2. Spawns background thread
3. Calls `send_request_sync()` in thread
4. Updates status based on result

---

##### `send_request_sync(middleware_addr: &str, request: &ClientRequest) -> Result<...>`

**Internal:** Synchronously sends a request and waits for response.

**Parameters:**
- `middleware_addr`: Middleware TCP address
- `request`: Request to send

**Returns:** `Result<MiddlewareResponse, Box<dyn Error>>`

**Protocol:**
1. Connect to middleware via TCP
2. Serialize request to JSON
3. Send JSON + newline delimiter
4. Read response line
5. Parse JSON response
6. Return response

## Communication Protocol

### Request Format

**TCP Stream with newline delimiters**

```
JSON_REQUEST\n
```

Example:
```
{"EncryptImage":{"request_id":1,"image_path":"photo.jpg"}}\n
```

### Response Format

```
JSON_RESPONSE\n
```

Example:
```
{"request_id":1,"status":"OK","message":"Image encrypted successfully","output_path":"photo.jpg.encrypted"}\n
```

## Threading Model

```
Main Thread (UI)
    │
    ├─▶ Background Worker Thread 1 (Request #1)
    │       └─▶ TCP Connection to Middleware
    │
    ├─▶ Background Worker Thread 2 (Request #2)
    │       └─▶ TCP Connection to Middleware
    │
    └─▶ Background Worker Thread 3 (Request #3)
            └─▶ TCP Connection to Middleware
```

**Thread Safety:**
- `RequestTracker` uses `Arc<Mutex<...>>` for thread-safe access
- Each request gets its own TCP connection
- No shared mutable state between worker threads

## Configuration

### Default Settings

| Setting | Value | Description |
|---------|-------|-------------|
| Username | `"user1"` | Default client username |
| Client IP | `"127.0.0.1"` | Localhost |
| Client Port | `8080` | Reserved (unused) |
| Middleware Address | `"127.0.0.1:9000"` | Default middleware location |

**To modify:** Edit the `main()` function:

```rust
fn main() {
    let client = Client::new(
        "your_username",      // Change username
        "192.168.1.100",      // Change client IP
        8080,                 // Change client port
        "192.168.1.50:9000"   // Change middleware address
    );
    client.start_ui();
}
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `"Image file not found"` | File path doesn't exist | Check file path |
| `"Connection refused"` | Middleware not running | Start middleware first |
| `"Invalid request format"` | Malformed JSON | Check request structure |
| Network timeout | Middleware unresponsive | Check network/firewall |

### Error Propagation

```rust
// Errors are captured and stored in RequestStatus
match client.request_encryption("invalid.jpg") {
    Ok(id) => println!("Queued as #{}", id),
    Err(e) => eprintln!("Error: {}", e),  // File not found
}
```

## Usage Examples

### Basic Usage

```rust
use client::Client;

fn main() {
    // Create client
    let client = Client::new("alice", "127.0.0.1", 8080, "127.0.0.1:9000");
    
    // Start interactive UI
    client.start_ui();
}
```

### Programmatic Usage

```rust
// Submit requests programmatically
let id1 = client.request_encryption("image1.jpg")?;
let id2 = client.request_encryption("image2.jpg")?;
let id3 = client.request_encryption("image3.jpg")?;

// Wait a bit for processing
std::thread::sleep(std::time::Duration::from_secs(2));

// Check results
client.check_status(id1);
client.check_status(id2);
client.check_status(id3);
```

### Batch Processing

```rust
// Queue multiple files
let files = vec!["img1.jpg", "img2.jpg", "img3.jpg", "img4.jpg"];
let mut request_ids = Vec::new();

for file in files {
    if let Ok(id) = client.request_encryption(file) {
        request_ids.push(id);
        println!("Queued {} as request #{}", file, id);
    }
}

// Monitor progress
loop {
    let pending = client.tracker.pending_count();
    if pending == 0 {
        println!("All requests completed!");
        break;
    }
    println!("Waiting for {} requests...", pending);
    std::thread::sleep(std::time::Duration::from_secs(1));
}
```

## Dependencies

```toml
[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

## Building and Running

### Build

```bash
cargo build --bin client
```

### Run

```bash
# Make sure middleware is running first!
cargo run --bin middleware

# In another terminal:
cargo run --bin client
```

### Run with Release Optimizations

```bash
cargo run --release --bin client
```

## Future Enhancements

### Planned Features

1. **Persistent Connection Mode**
   - Reuse TCP connections for multiple requests
   - Reduce connection overhead

2. **Progress Notifications**
   - Real-time progress updates from middleware
   - Progress bars for long operations

3. **Request Cancellation**
   - Cancel pending/in-progress requests
   - Abort ongoing operations

4. **Configuration File**
   - Load settings from `config.toml`
   - Support multiple middleware endpoints

5. **P2P Direct Communication**
   - Use client port 8080 for peer connections
   - Direct client-to-client encrypted sharing

6. **Request History Persistence**
   - Save request history to disk
   - Resume after client restart

7. **Batch Operations**
   - `encrypt-all <directory>` command
   - Wildcard support: `encrypt *.jpg`

## Troubleshooting

### Client won't connect to middleware

**Symptoms:** `"Connection refused"` error

**Solutions:**
1. Ensure middleware is running: `cargo run --bin middleware`
2. Check middleware address is correct
3. Verify firewall isn't blocking port 9000

### Requests stuck in "Pending" state

**Symptoms:** Requests never complete

**Solutions:**
1. Check middleware logs for errors
2. Verify file paths are correct
3. Ensure middleware has file system permissions

### "Image file not found" errors

**Symptoms:** Valid files rejected

**Solutions:**
1. Use absolute paths: `/full/path/to/image.jpg`
2. Check current working directory
3. Verify file permissions

## Performance Considerations

### Concurrency

- Each request spawns a new thread
- Threads are lightweight but consume resources
- Recommended max: ~100 concurrent requests
- For more, consider implementing a thread pool

### Network

- Each request opens a new TCP connection
- Connection overhead: ~1-5ms on localhost
- For high-frequency operations, use persistent connections

### Memory

- Each request: ~1KB memory overhead
- Request history stored in memory
- Consider clearing old completed requests for long-running sessions

## Security Considerations

### Current Implementation

⚠️ **This is a prototype with no security measures!**

### Security Gaps

1. **No authentication** - Anyone can connect
2. **No encryption in transit** - TCP plaintext
3. **No authorization** - No access control
4. **No input validation** - Path traversal possible

### Production Requirements

For production use, implement:

1. **TLS/SSL** for encrypted communication
2. **Authentication** (API keys, OAuth, etc.)
3. **Authorization** (user permissions)
4. **Input sanitization** (prevent path traversal)
5. **Rate limiting** (prevent abuse)

## License

Part of the Cloud P2P Controlled Image Sharing Project.

## Contact

For questions or contributions, contact the project maintainers.