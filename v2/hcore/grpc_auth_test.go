package hcore

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type authProbe struct {
	health.UnimplementedHealthServer
	unaryCalls  atomic.Int32
	streamCalls atomic.Int32
}

func (p *authProbe) Check(context.Context, *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
	p.unaryCalls.Add(1)
	return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
}

func (p *authProbe) Watch(_ *health.HealthCheckRequest, stream health.Health_WatchServer) error {
	p.streamCalls.Add(1)
	return stream.Send(&health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING})
}

func TestCoreRPCAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name          string
		serverSecret  string
		clientSecrets []string
		allowed       bool
	}{
		{name: "correct", serverSecret: "private-key", clientSecrets: []string{"private-key"}, allowed: true},
		{name: "missing", serverSecret: "private-key"},
		{name: "wrong", serverSecret: "private-key", clientSecrets: []string{"incorrect"}},
		{name: "empty", serverSecret: "private-key", clientSecrets: []string{""}},
		{name: "duplicate", serverSecret: "private-key", clientSecrets: []string{"private-key", "other"}},
		{name: "legacy-mobile-mode", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer(coreRPCAuthOptions(tc.serverSecret)...)
			probe := &authProbe{}
			health.RegisterHealthServer(server, probe)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			conn, err := grpc.NewClient("passthrough:///core-auth-test",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if len(tc.clientSecrets) > 0 {
				ctx = metadata.NewOutgoingContext(ctx, metadata.MD{coreRPCSecretHeader: tc.clientSecrets})
			}
			client := health.NewHealthClient(conn)
			_, unaryErr := client.Check(ctx, &health.HealthCheckRequest{})
			stream, streamErr := client.Watch(ctx, &health.HealthCheckRequest{})
			if streamErr == nil {
				_, streamErr = stream.Recv()
			}
			if tc.allowed {
				if unaryErr != nil || streamErr != nil {
					t.Fatalf("authorized calls failed: unary=%v stream=%v", unaryErr, streamErr)
				}
				if probe.unaryCalls.Load() != 1 || probe.streamCalls.Load() != 1 {
					t.Fatal("authorized handlers did not run")
				}
			} else {
				if status.Code(unaryErr) != codes.Unauthenticated || status.Code(streamErr) != codes.Unauthenticated {
					t.Fatalf("untrusted calls accepted: unary=%v stream=%v", unaryErr, streamErr)
				}
				if probe.unaryCalls.Load() != 0 || probe.streamCalls.Load() != 0 {
					t.Fatal("untrusted request reached a handler")
				}
			}
		})
	}
}
