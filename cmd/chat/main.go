package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/yutianwu/chat-demo/chat"
)

func main() {
	var port int
	var peer string
	name := flag.String("name", "", "Your name")
	flag.IntVar(&port, "port", 0, "Port to listen on")
	flag.StringVar(&peer, "peer", "", "Peer address to connect to (host:port)")
	flag.Parse()

	if *name == "" {
		fmt.Println("Please provide your name with -name flag")
		os.Exit(1)
	}

	if port == 0 {
		fmt.Println("Please specify a port to listen on with -port flag")
		os.Exit(1)
	}

	// Create session
	session, err := chat.NewSession(*name, *name)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Listening on port %d\n", port)

	// If peer is specified, try to connect
	var conn net.Conn
	if peer != "" {
		fmt.Printf("Connecting to peer at %s...\n", peer)
		// Try to connect with retries
		for i := 0; i < 3; i++ {
			conn, err = net.Dial("tcp", peer)
			if err == nil {
				fmt.Printf("Connected to peer %s\n", peer)
				// Initiator sends their key exchange first
				handleConnection(conn, session)
				break
			}
			log.Printf("Connection attempt %d failed: %v", i+1, err)
			time.Sleep(time.Second)
		}
	}

	// If not connected to peer, wait for incoming connection
	if conn == nil {
		fmt.Println("Waiting for peer connection...")
		conn, err = listener.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}
		fmt.Printf("Peer connected from %s\n", conn.RemoteAddr())

		// Receiver waits for key exchange first
		handleConnection(conn, session)
	}

	// Handle chat
	handleChat(conn, session, *name)
}

func handleConnection(conn net.Conn, session *chat.Session) {
	// Perform key exchange
	data, err := session.InitiateKeyExchange()
	if err != nil {
		log.Printf("Failed to initiate key exchange: %v", err)
		return
	}

	// Send key exchange data
	_, err = conn.Write(data)
	if err != nil {
		log.Printf("Failed to send key exchange data: %v", err)
		return
	}

	// Read key exchange response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Failed to read key exchange response: %v", err)
		return
	}

	// Handle key exchange response
	if err := session.HandleKeyExchange(buffer[:n]); err != nil {
		log.Printf("Failed to handle key exchange: %v", err)
		return
	}

	log.Printf("Key exchange completed successfully")
}

func handleChat(conn net.Conn, session *chat.Session, name string) {
	defer conn.Close()

	// Handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		fmt.Println("\nClosing connection...")
		conn.Close()
		os.Exit(0)
	}()

	// Start message receiver
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("Connection closed: %v", err)
				os.Exit(0)
			}

			var msg chat.Message
			if err := json.Unmarshal(buffer[:n], &msg); err != nil {
				log.Printf("Error unmarshaling message: %v", err)
				continue
			}

			peer, decrypted, err := session.ReceiveMessage(&msg)
			if err != nil {
				log.Printf("Error decrypting: %v", err)
				continue
			}

			fmt.Printf("\n%s: %s\n> ", peer, decrypted)
		}
	}()

	// Start message sender
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Chat started. Type your messages (quit to exit):\n")
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		if input == "quit" {
			return
		}

		msg, err := session.SendMessage(input)
		if err != nil {
			log.Printf("Error encrypting: %v", err)
			continue
		}

		// Serialize message with metadata
		data, err := json.Marshal(msg)
		if err != nil {
			log.Printf("Error marshaling message: %v", err)
			continue
		}

		_, err = conn.Write(data)
		if err != nil {
			log.Printf("Error sending: %v", err)
			return
		}
	}
}
