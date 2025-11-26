package types

import (
	"net"
	"testing"

	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// -----------------------------------------------------------------------------
// Fake Provider (same as in server tests)
// -----------------------------------------------------------------------------

type FakeProvider struct {
	CreateCtxCalled bool
}

func (f *FakeProvider) CreateCryptoContext(c CryptoContext) error {
	f.CreateCtxCalled = true
	return nil
}

func (f *FakeProvider) DestroyCryptoContext(c CryptoContext) error            { return nil }
func (f *FakeProvider) IsCryptoContextExisting(c CryptoContext) (bool, error) { return true, nil }
func (f *FakeProvider) GetNamespaces(c CryptoContext) ([]string, error) {
	return []string{"ns1", "ns2"}, nil
}
func (f *FakeProvider) GenerateRandom(c CryptoContext, n int) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}
func (f *FakeProvider) Hash(p CryptoHashParameter, msg []byte) ([]byte, error) {
	return []byte("hashed"), nil
}
func (f *FakeProvider) Encrypt(id CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("encrypted"), nil
}
func (f *FakeProvider) Decrypt(id CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("decrypted"), nil
}
func (f *FakeProvider) Sign(id CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("signature"), nil
}
func (f *FakeProvider) Verify(id CryptoIdentifier, data []byte, sig []byte) (bool, error) {
	return true, nil
}
func (f *FakeProvider) GetKeys(filter CryptoFilter) (*CryptoKeySet, error) {
	return &CryptoKeySet{Keys: []CryptoKey{{Version: "v1"}}}, nil
}
func (f *FakeProvider) GetKey(id CryptoIdentifier) (*CryptoKey, error) {
	return &CryptoKey{Version: "v1"}, nil
}
func (f *FakeProvider) GenerateKey(p CryptoKeyParameter) error          { return nil }
func (f *FakeProvider) IsKeyExisting(id CryptoIdentifier) (bool, error) { return true, nil }
func (f *FakeProvider) DeleteKey(id CryptoIdentifier) error             { return nil }
func (f *FakeProvider) RotateKey(id CryptoIdentifier) error             { return nil }
func (f *FakeProvider) GetSupportedKeysAlgs() []KeyType                 { return []KeyType{"ed25519"} }
func (f *FakeProvider) GetSupportedHashAlgs() []HashAlgorithm           { return []HashAlgorithm{"sha2-256"} }

// -----------------------------------------------------------------------------
// Test helper: start server
// -----------------------------------------------------------------------------

func startServer(t *testing.T, provider CryptoProvider) (pb.CryptoProviderServiceClient, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}

	server := grpc.NewServer()
	pb.RegisterCryptoProviderServiceServer(server, NewServer(provider))

	go server.Serve(lis)

	// Build gRPC client
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client error: %v", err)
	}

	client := pb.NewCryptoProviderServiceClient(conn)

	cleanup := func() {
		server.Stop()
		lis.Close()
	}

	return client, cleanup
}

// -----------------------------------------------------------------------------
// CLIENT TESTS
// -----------------------------------------------------------------------------

func TestClient_CreateCryptoContext(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	err := client.CreateCryptoContext(CryptoContext{Namespace: "test"})
	if err != nil {
		t.Fatalf("rpc error: %v", err)
	}

	if !fake.CreateCtxCalled {
		t.Errorf("expected CreateCryptoContext to be called on provider")
	}
}

func TestClient_GetNamespaces(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	ns, err := client.GetNamespaces(CryptoContext{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(ns) != 2 {
		t.Errorf("expected 2 namespaces, got %v", ns)
	}
}

func TestClient_GenerateRandom(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	r, err := client.GenerateRandom(CryptoContext{}, 3)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(r) != 3 {
		t.Errorf("expected len=3, got %d", len(r))
	}
}

func TestClient_Hash(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	r, err := client.Hash(CryptoHashParameter{}, []byte("hello"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if string(r) != "hashed" {
		t.Errorf("expected hashed, got %s", r)
	}
}

func TestClient_EncryptDecrypt(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	enc, err := client.Encrypt(CryptoIdentifier{}, []byte("hi"))
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	if string(enc) != "encrypted" {
		t.Errorf("bad encrypt: %s", enc)
	}

	dec, err := client.Decrypt(CryptoIdentifier{}, enc)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if string(dec) != "decrypted" {
		t.Errorf("bad decrypt: %s", dec)
	}
}

func TestClient_SignVerify(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	sig, err := client.Sign(CryptoIdentifier{}, []byte("hello"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if string(sig) != "signature" {
		t.Errorf("bad signature: %s", sig)
	}

	valid, err := client.Verify(CryptoIdentifier{}, []byte("hello"), sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if !valid {
		t.Error("verify should be true")
	}
}

func TestClient_GetKeys(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	ks, err := client.GetKeys(CryptoFilter{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(ks.Keys) != 1 {
		t.Errorf("expected 1 key")
	}
}

func TestClient_GetKey(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	k, err := client.GetKey(CryptoIdentifier{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if k.Version != "v1" {
		t.Errorf("wrong version: %s", k.Version)
	}
}

func TestClient_GetSupportedKeyAlgs(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	types := client.GetSupportedKeysAlgs()
	if len(types) != 1 {
		t.Errorf("expected 1 alg, got %d", len(types))
	}
}

func TestClient_GetSupportedHashAlgs(t *testing.T) {
	fake := &FakeProvider{}
	pbClient, cleanup := startServer(t, fake)
	defer cleanup()

	client := NewCryptoProviderClient(pbClient)

	algs := client.GetSupportedHashAlgs()
	if len(algs) != 1 {
		t.Errorf("expected 1 alg, got %d", len(algs))
	}
}
