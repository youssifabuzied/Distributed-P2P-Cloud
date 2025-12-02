# Distributed-P2P-Cloud

This project demonstrates a simple distributed application with separate client and server components written in Rust.

## Prerequisites

You must have the Rust toolchain installed. Follow the official installation guide here:
[https://doc.rust-lang.org/book/ch01-01-installation.html](https://doc.rust-lang.org/book/ch01-01-installation.html)

## Setup and Running the Application

You can follow these steps in **one flow**.

### Step 1: Clone the repository

```bash
git clone https://github.com/youssifabuzied/Distributed-P2P-Cloud.git
```

### Step 2: Navigate into the project directory

```bash
cd Distributed-P2P-Cloud
```

### Step 3: Add server URLs

In `server/server_urls.json`, add the corresponding server URLs. Example:

```json
[
    "http://10.185.59.183",
    "http://10.185.59.251"
]
```

### Step 4: Open the first terminal and run the server

```bash
cargo run --bin server
```

### Step 5: Open the second terminal and run the client GUI

```bash
cargo run --bin client_gui
```

### Step 6: Open the third terminal and run the database

```bash
cd database
rm database.db
python3 main.py
```
