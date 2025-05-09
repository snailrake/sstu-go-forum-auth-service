package main

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"net"
	"os"

	"sstu-go-forum-auth-service/internal/utils"

	pb "github.com/snailrake/sstu-auth-proto/proto/auth"
)

var logger zerolog.Logger

func init() {
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

type authServer struct {
	pb.UnimplementedAuthServiceServer
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to listen on port 50051")
	}
	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, &authServer{})
	reflection.Register(s)

	logger.Info().Msg("Starting gRPC server on :50051")
	if err := s.Serve(lis); err != nil {
		logger.Fatal().Err(err).Msg("failed to serve gRPC server")
	}
}

func (s *authServer) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	logger.Debug().Str("token", req.Token).Msg("verifying token")
	claims, err := utils.VerifyToken(req.Token)
	if err != nil {
		logger.Error().Err(err).Msg("failed to verify token")
		return nil, err
	}
	structClaims, err := structpb.NewStruct(claims)
	if err != nil {
		logger.Error().Err(err).Msg("failed to marshal claims")
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	logger.Info().Msg("token verified successfully")
	return &pb.VerifyTokenResponse{Claims: structClaims}, nil
}
