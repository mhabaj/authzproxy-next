// cmd/authzproxy/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"authzproxy/internal/config"
	"authzproxy/internal/server"
)

func main() {
	// Parse command line arguments
	configPath := flag.String("config", "", "path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create server
	srv, err := server.NewFromConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Handle signals for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		fmt.Println("Starting server...")
		if err := srv.Start(); err != nil {
			errCh <- err
		}
	}()

	// Wait for termination signal or error
	select {
	case <-ctx.Done():
		fmt.Println("Shutting down gracefully...")
	case err := <-errCh:
		fmt.Printf("Server error: %v\n", err)
	}

	// Shut down server gracefully
	if err := srv.Stop(context.Background()); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	fmt.Println("Server stopped successfully")
}
