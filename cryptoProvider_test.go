package core

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCreateCryptoEngine_ProviderAvailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	server := grpc.NewServer()

	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	engine, cleanup, err := CreateCryptoEngine(
		ctx,
		listener.Addr().String(),
		insecure.NewCredentials(),
	)

	if err != nil {
		t.Fatalf("expected provider to be available, got error: %v", err)
	}

	if engine == nil {
		t.Fatal("expected crypto engine, got nil")
	}

	if cleanup == nil {
		t.Fatal("expected cleanup function, got nil")
	}

	cleanup()
}

func TestCreateCryptoEngine_ProviderUnavailable(t *testing.T) {
	// Reserve a real TCP port first, then release it.
	// This gives us a valid address where no gRPC server is running.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}

	addr := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release port: %v", err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		250*time.Millisecond,
	)
	defer cancel()

	engine, cleanup, err := CreateCryptoEngine(
		ctx,
		addr,
		insecure.NewCredentials(),
	)

	if err == nil {
		t.Fatal("expected error when crypto provider is unavailable")
	}

	if engine != nil {
		t.Fatalf("expected nil engine, got %#v", engine)
	}

	if cleanup != nil {
		t.Fatal("expected nil cleanup function")
	}
}

func TestCreateCryptoEngine_ContextCancelled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}

	addr := listener.Addr().String()
	_ = listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	engine, cleanup, err := CreateCryptoEngine(
		ctx,
		addr,
		insecure.NewCredentials(),
	)

	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if engine != nil {
		t.Fatal("expected nil engine")
	}

	if cleanup != nil {
		t.Fatal("expected nil cleanup")
	}
}
