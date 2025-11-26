package types_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/eclipse-xfsc/crypto-provider-core/v2/types"
	pb "github.com/eclipse-xfsc/crypto-provider-core/v2/types/proto"
	"google.golang.org/grpc"
)

// -----------------------------------------------------------------------------
// Fake Provider (Mock)
// -----------------------------------------------------------------------------

type FakeProvider struct {
	CreateContextCalled bool
}

func (f *FakeProvider) CreateCryptoContext(ctx types.CryptoContext) error {
	f.CreateContextCalled = true
	return nil
}
func (f *FakeProvider) DestroyCryptoContext(ctx types.CryptoContext) error { return nil }
func (f *FakeProvider) IsCryptoContextExisting(ctx types.CryptoContext) (bool, error) {
	return true, nil
}
func (f *FakeProvider) GetNamespaces(ctx types.CryptoContext) ([]string, error) {
	return []string{"ns1", "ns2"}, nil
}
func (f *FakeProvider) GenerateRandom(ctx types.CryptoContext, n int) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}
func (f *FakeProvider) Hash(p types.CryptoHashParameter, msg []byte) ([]byte, error) {
	return []byte("hashed"), nil
}
func (f *FakeProvider) Encrypt(id types.CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("encrypted"), nil
}
func (f *FakeProvider) Decrypt(id types.CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("decrypted"), nil
}
func (f *FakeProvider) Sign(id types.CryptoIdentifier, data []byte) ([]byte, error) {
	return []byte("signature"), nil
}
func (f *FakeProvider) Verify(id types.CryptoIdentifier, data []byte, sig []byte) (bool, error) {
	return true, nil
}
func (f *FakeProvider) GetKeys(filter types.CryptoFilter) (*types.CryptoKeySet, error) {
	return &types.CryptoKeySet{
		Keys: []types.CryptoKey{
			{Version: "v1"},
		},
	}, nil
}
func (f *FakeProvider) GetKey(id types.CryptoIdentifier) (*types.CryptoKey, error) {
	return &types.CryptoKey{Version: "v1"}, nil
}
func (f *FakeProvider) GenerateKey(p types.CryptoKeyParameter) error { return nil }
func (f *FakeProvider) IsKeyExisting(id types.CryptoIdentifier) (bool, error) {
	return true, nil
}
func (f *FakeProvider) DeleteKey(id types.CryptoIdentifier) error { return nil }
func (f *FakeProvider) RotateKey(id types.CryptoIdentifier) error { return nil }
func (f *FakeProvider) GetSupportedKeysAlgs() []types.KeyType {
	return []types.KeyType{types.KeyType("ed25519")}
}
func (f *FakeProvider) GetSupportedHashAlgs() []types.HashAlgorithm {
	return []types.HashAlgorithm{types.HashAlgorithm("sha2-256")}
}

// -----------------------------------------------------------------------------
// Helper: Start test server
// -----------------------------------------------------------------------------

func startTestServer(t *testing.T, provider types.CryptoProvider) (pb.CryptoProviderServiceClient, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterCryptoProviderServiceServer(srv, types.NewServer(provider))

	go srv.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure(),
		grpc.WithBlock(), grpc.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := pb.NewCryptoProviderServiceClient(conn)

	cleanup := func() {
		srv.Stop()
		conn.Close()
		lis.Close()
	}

	return client, cleanup
}

// -----------------------------------------------------------------------------
// TESTS
// -----------------------------------------------------------------------------

func TestCreateCryptoContext(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	_, err := client.CreateCryptoContext(context.Background(), &pb.CreateContextRequest{
		Ctx: &pb.CryptoContext{Namespace: "test"},
	})
	if err != nil {
		t.Fatalf("rpc error: %v", err)
	}

	if !fake.CreateContextCalled {
		t.Errorf("FakeProvider.CreateCryptoContext was not called")
	}
}

func TestGetNamespaces(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GetNamespaces(context.Background(), &pb.GetNamespacesRequest{
		Ctx: &pb.CryptoContext{},
	})
	if err != nil {
		t.Fatalf("rpc error: %v", err)
	}

	if len(resp.Namespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %v", resp.Namespaces)
	}
}

func TestGenerateRandom(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GenerateRandom(context.Background(), &pb.GenerateRandomRequest{
		Ctx:    &pb.CryptoContext{},
		Number: 3,
	})
	if err != nil {
		t.Fatalf("rpc error: %v", err)
	}

	if len(resp.Random) != 3 {
		t.Errorf("expected 3 bytes, got %v", resp.Random)
	}
}

func TestHash(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.Hash(context.Background(), &pb.HashRequest{
		Parameter: &pb.CryptoHashParameter{
			Identifier: &pb.CryptoIdentifier{},
		},
		Msg: []byte("hello"),
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if string(resp.Hash) != "hashed" {
		t.Errorf("expected hashed, got %s", resp.Hash)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	enc, err := client.Encrypt(context.Background(), &pb.EncryptRequest{
		Identifier: &pb.CryptoIdentifier{},
		Data:       []byte("hello"),
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if string(enc.Cipher) != "encrypted" {
		t.Errorf("bad enc: %s", enc.Cipher)
	}

	dec, err := client.Decrypt(context.Background(), &pb.DecryptRequest{
		Identifier: &pb.CryptoIdentifier{},
		Data:       enc.Cipher,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(dec.Plain) != "decrypted" {
		t.Errorf("bad dec: %s", dec.Plain)
	}
}

func TestSignVerify(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	sig, err := client.Sign(context.Background(), &pb.SignRequest{
		Identifier: &pb.CryptoIdentifier{},
		Data:       []byte("abc"),
	})
	if err != nil {
		t.Fatalf("sign error: %v", err)
	}

	if string(sig.Signature) != "signature" {
		t.Errorf("signature invalid")
	}

	ver, err := client.Verify(context.Background(), &pb.VerifyRequest{
		Identifier: &pb.CryptoIdentifier{},
		Data:       []byte("abc"),
		Signature:  sig.Signature,
	})
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	if !ver.Valid {
		t.Errorf("expected true")
	}
}

func TestGetKeys(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GetKeys(context.Background(), &pb.GetKeysRequest{
		Filter: &pb.CryptoFilter{},
	})
	if err != nil {
		t.Fatalf("GetKeys error: %v", err)
	}

	if len(resp.Keys.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(resp.Keys.Keys))
	}
}

func TestGetKey(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GetKey(context.Background(), &pb.GetKeyRequest{
		Identifier: &pb.CryptoIdentifier{},
	})
	if err != nil {
		t.Fatalf("GetKey error: %v", err)
	}

	if resp.Key.Version != "v1" {
		t.Errorf("wrong version")
	}
}

func TestGetSupportedKeyAlgs(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GetSupportedKeysAlgs(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(resp.Types) != 1 {
		t.Errorf("expected 1 type")
	}
}

func TestGetSupportedHashAlgs(t *testing.T) {
	fake := &FakeProvider{}
	client, cleanup := startTestServer(t, fake)
	defer cleanup()

	resp, err := client.GetSupportedHashAlgs(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if len(resp.Algorithms) != 1 {
		t.Errorf("expected 1 hash alg")
	}
}
