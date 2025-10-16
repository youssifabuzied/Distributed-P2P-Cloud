# Distributed-P2P-Cloud

This project demonstrates a simple distributed application with separate client and server components written in Rust.

## Prerequisites

You must have the Rust toolchain installed. Follow the official installation guide here:  
[Rust Installation Guide](https://doc.rust-lang.org/book/ch01-01-installation.html)

## Setup and Running the Application

You can follow these steps in **one flow**. You will need two terminal windows: one for the server and one for the client.

```bash
# Step 1: Clone the repository
git clone https://github.com/youssifabuzied/Distributed-P2P-Cloud.git

# Step 2: Navigate into the project directory
cd Distributed-P2P-Cloud

# Step 3: Open the first terminal and run the server
cargo run --bin server

# Step 4: Open the second terminal and run the client
cargo run --bin client_app

# Step 5: Once the client is running, you can test commands directly.
# For example, to encrypt a file:
encrypt resources/default_image.png
