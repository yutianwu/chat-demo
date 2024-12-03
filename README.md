# Secure Chat Demo

A secure, end-to-end encrypted chat application built in Go. It uses the Triple Diffie-Hellman (3DH) key exchange protocol for secure key establishment and provides encrypted messaging between two parties.

## Features

- End-to-end encryption using Triple Diffie-Hellman (3DH) key exchange
- Secure message encryption with key rotation
- Command-line interface for easy use
- Real-time messaging between two parties
- Custom logging system with configurable log levels

## Building

```bash
go build -o chat_bin ./cmd/chat
```

## Usage

The chat application supports two-party communication. One party acts as the listener (Alice) and the other as the peer (Bob).

### Starting Alice (Listener)

```bash
./chat_bin -name Alice -port 8080
```

### Starting Bob (Peer)

```bash
./chat_bin -name Bob -port 8081 -peer localhost:8080
```

### Command Line Arguments

- `-name`: Your username in the chat (required)
- `-port`: Port to listen on (required)
- `-peer`: Address of the peer to connect to (required for the second party)

### Chat Commands

- Type your message and press Enter to send
- Type `quit` to exit the chat

## Security Features

- Triple Diffie-Hellman (3DH) key exchange for secure key establishment
- Unique session keys for each conversation
- Key rotation after each message
- Encrypted message transmission
- Sequence number validation to prevent replay attacks

## Implementation Details

- Written in Go
- Uses standard Go crypto libraries
- Custom logging system with multiple log levels
- TCP-based communication with JSON message encoding
- Thread-safe message handling

## Project Structure

```
chat-demo/
├── cmd/
│   └── chat/
│       └── main.go       # Main application entry point
├── chat/
│   └── session.go        # Chat session implementation
├── crypto/
│   ├── keys.go          # Cryptographic key operations
│   └── encryption.go    # Message encryption/decryption
└── logger/
    └── logger.go        # Custom logging package
```

## Development

### Prerequisites

- Go 1.21 or later
- `github.com/gorilla/websocket`

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yutianwu/chat-demo.git

# Build the binary
cd chat-demo
go build -o chat_bin ./cmd/chat
```

## Example Chat Session

1. Start Alice's session:
```bash
./chat_bin -name Alice -port 8080
```

2. In another terminal, start Bob's session:
```bash
./chat_bin -name Bob -port 8081 -peer localhost:8080
```

3. Start chatting! Messages will appear with the sender's name:
```
Alice: Hello Bob!
Bob: Hi Alice! This is encrypted.
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Add your license here]
