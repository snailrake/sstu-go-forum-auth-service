package handler

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"sstu-go-forum-auth-service/internal/utils"

	pb "github.com/snailrake/sstu-auth-proto/proto/auth"
)

type GrpcHandler struct {
	pb.UnimplementedAuthServiceServer
}

func NewGrpcHandler() *GrpcHandler {
	return &GrpcHandler{}
}

func (h *GrpcHandler) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	log.Debug().Str("token", req.Token).Msg("verifying token")
	claims, err := utils.VerifyToken(req.Token)
	if err != nil {
		log.Error().Err(err).Msg("failed to verify token")
		return nil, err
	}
	structClaims, err := structpb.NewStruct(claims)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal claims")
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	log.Info().Msg("token verified successfully")
	return &pb.VerifyTokenResponse{Claims: structClaims}, nil
}
