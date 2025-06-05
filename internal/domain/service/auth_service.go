package service

import (
	"context"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/pkg/jwt"
	utils "github.com/dropboks/auth-service/pkg/utils"
	fileProto "github.com/dropboks/proto-file/pkg/fpb"
	userProto "github.com/dropboks/proto-user/pkg/upb"
	_utils "github.com/dropboks/sharedlib/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type (
	AuthService interface {
		LoginService(req dto.LoginRequest) (string, error)
		RegisterService(req dto.RegisterRequest) (string, error)
		VerifyService(token string) (string, error)
		LogoutService(token string) error
	}
	authService struct {
		authRepository    repository.AuthRepository
		userServiceClient userProto.UserServiceClient
		fileServiceClient fileProto.FileServiceClient
		logger            zerolog.Logger
	}
)

func New(authRepository repository.AuthRepository, userServiceClient userProto.UserServiceClient, fileServiceClient fileProto.FileServiceClient, logger zerolog.Logger) AuthService {
	return &authService{
		authRepository:    authRepository,
		userServiceClient: userServiceClient,
		fileServiceClient: fileServiceClient,
		logger:            logger,
	}
}

func (a *authService) VerifyService(token string) (string, error) {
	c := context.Background()
	key := "session:" + token
	err := a.authRepository.CheckAccessToken(c, key)
	if err != nil {
		return "", err
	}
	claims, err := jwt.ValidateJWT(token)
	if err != nil {
		a.logger.Error().Err(err).Msg("invalid jwt")
		return "", err
	}
	return claims.UserId, nil
}

func (a *authService) LogoutService(token string) error {
	c := context.Background()
	key := "session:" + token
	err := a.authRepository.RemoveAccessToken(c, key)
	if err != nil {
		return err
	}
	return nil
}

func (a *authService) RegisterService(req dto.RegisterRequest) (string, error) {
	c := context.Background()
	exist, err := a.userServiceClient.GetUserByEmail(c, &userProto.Email{
		Email: req.Email,
	})
	if err != nil {
		a.logger.Error().Err(err).Msg("Error Query Get User By Email")
		// handle error from grpc
		return "", err
	}
	if exist != nil {
		a.logger.Error().Msg("User with this email exist")
		return "", dto.Err_CONFLICT_EMAIL_EXIST
	}
	password, err := utils.HashPassword(req.Password)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error hashing password")
	}
	image, err := _utils.FileToByte(req.Image)
	if err != nil {
		a.logger.Error().Err(err).Msg("error converting image")
		return "", dto.Err_INTERNAL_CONVERT_IMAGE
	}
	imageReq := &fileProto.Image{
		Image: image,
	}
	imageName, err := a.fileServiceClient.SaveProfileImage(c, imageReq)
	if err != nil {
		// handle error from grpc
		a.logger.Error().Err(err).Msg("Error uploading image to file service")
		return "", err
	}
	userId := uuid.New().String()
	user := &userProto.User{
		Id:       userId,
		FullName: req.FullName,
		Image:    imageName.GetName(),
		Email:    req.Email,
		Password: password,
	}
	_, err = a.userServiceClient.CreateUser(c, user)
	if err != nil {
		// handle grpc error
		_, errRemove := a.fileServiceClient.RemoveProfileImage(c, imageName)
		if errRemove != nil {
			// handle grpc err
		}
		return "", err
	}
	token, err := jwt.GenerateToken(userId)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error JWT Signing")
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	sessionKey := "session:" + token
	err = a.authRepository.SetAccessToken(c, sessionKey, token)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error saving token to Redis")
		return "", dto.Err_INTERNAL_SET_TOKEN
	}
	return token, nil
}

func (a *authService) LoginService(req dto.LoginRequest) (string, error) {
	c := context.Background()
	user, err := a.userServiceClient.GetUserByEmail(c, &userProto.Email{
		Email: req.Email,
	})
	if err != nil {
		a.logger.Error().Err(err).Msg("Error Query Get User By Email")
		// handle error based on return codes from grpc
		return "", err
	}
	ok := utils.HashPasswordCompare(req.Password, user.Password)
	if !ok {
		a.logger.Error().Err(err).Msg("Password doesn't match")
		return "", dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH
	}
	token, err := jwt.GenerateToken(user.Id)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error JWT Signing")
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	// if use redis with userid as a key, just one session is registered
	// use another key like session:token
	sessionKey := "session:" + token
	err = a.authRepository.SetAccessToken(c, sessionKey, token)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error saving token to Redis")
		return "", dto.Err_INTERNAL_SET_TOKEN
	}
	return token, nil
}
