package main

import (
	"net"
	"os"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/snailrake/sstu-auth-proto/proto/auth"
	"sstu-go-forum-auth-service/internal/handler"
)

var logger zerolog.Logger

func init() {
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

func main() { // TODO: вынести обработку в отдельный handler
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to listen on port 50051")
	}

	s := grpc.NewServer()
	pb.RegisterAuthServiceServer(s, handler.NewGrpcHandler())
	reflection.Register(s)

	logger.Info().Msg("Starting gRPC server on :50051")
	if err := s.Serve(lis); err != nil {
		logger.Fatal().Err(err).Msg("failed to serve gRPC server")
	}
}
