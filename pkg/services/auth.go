package services

import (
	"context"
	"net/http"

	"github.com/Ansalps/genzone-admin-svc/pkg/db"
	"github.com/Ansalps/genzone-admin-svc/pkg/models"
	"github.com/Ansalps/genzone-admin-svc/pkg/pb"
	"github.com/Ansalps/genzone-admin-svc/pkg/utils"
)

type Server struct {
	H   db.Handler
	Jwt utils.JwtWrapper
	pb.UnimplementedAuthServiceServer
}

func (s *Server) Login(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	var admin models.Admin
	if result := s.H.DB.Where(&models.Admin{Email: req.Email}).First(&admin); result.Error != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}
	//match := utils.CheckPasswordHash(req.Password, user.Password)
	if req.Password != admin.Password {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}
	token, _ := s.Jwt.GenerateToken(admin, "admin")
	return &pb.AdminLoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}
func (s *Server) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	claims, err := s.Jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateResponse{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		}, nil
	}
	var admin models.Admin
	if result := s.H.DB.Where(&models.Admin{Email: claims.Email}).First(&admin); result.Error != nil {
		return &pb.ValidateResponse{
			Status: http.StatusNotFound,
			Error:  "admin not found",
		}, nil
	}
	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: int64(admin.ID),
	}, nil
}
