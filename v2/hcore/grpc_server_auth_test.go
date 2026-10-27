package hcore

import (
	"net"
	"testing"
)

func TestCoreRPCBindFailureNeverPublishesServer(t *testing.T) {
	// The preliminary port check probes 127.0.0.1. Occupy another loopback
	// address to deterministically fail the actual bind after that check.
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("second loopback address unavailable: %v", err)
	}
	defer listener.Close()
	mode := SetupMode_GRPC_NORMAL_INSECURE
	t.Cleanup(func() {
		if server := grpcServer[mode]; server != nil {
			server.Stop()
			delete(grpcServer, mode)
		}
	})
	for attempt := 0; attempt < 2; attempt++ {
		_, err := StartGrpcServerByMode(listener.Addr().String(), mode, "private-key")
		if err == nil {
			t.Fatalf("attempt %d reported successful initialization despite the occupied port", attempt)
		}
		if grpcServer[mode] != nil {
			t.Fatal("failed bind published a server that would let Setup skip native initialization on retry")
		}
	}
}
