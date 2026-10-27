package hcore

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const coreRPCSecretHeader = "x-hiddify-secret"

func coreRPCAuthOptions(secret string) []grpc.ServerOption {
	// Mobile/native launchers without a secret keep their existing transport.
	// The desktop launcher always supplies a per-process secret.
	if secret == "" {
		return nil
	}
	authorized := func(ctx context.Context) bool {
		values := metadata.ValueFromIncomingContext(ctx, coreRPCSecretHeader)
		return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(secret)) == 1
	}
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if !authorized(ctx) {
				return nil, status.Error(codes.Unauthenticated, "invalid core credentials")
			}
			return handler(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if !authorized(stream.Context()) {
				return status.Error(codes.Unauthenticated, "invalid core credentials")
			}
			return handler(srv, stream)
		}),
	}
}
