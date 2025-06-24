package service

import (
	"context"
	"encoding/json"
	"fmt"

	dto "github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/pkg/constant"
	"github.com/dropboks/auth-service/pkg/jwt"
	utils "github.com/dropboks/auth-service/pkg/utils"
	fpb "github.com/dropboks/proto-file/pkg/fpb"
	upb "github.com/dropboks/proto-user/pkg/upb"
	_dto "github.com/dropboks/sharedlib/dto"
	_utils "github.com/dropboks/sharedlib/utils"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		userServiceClient upb.UserServiceClient
		fileServiceClient fpb.FileServiceClient
		logger            zerolog.Logger
		js                jetstream.JetStream
	}
)

func New(authRepository repository.AuthRepository, userServiceClient upb.UserServiceClient, fileServiceClient fpb.FileServiceClient, logger zerolog.Logger, js jetstream.JetStream) AuthService {
	return &authService{
		authRepository:    authRepository,
		userServiceClient: userServiceClient,
		fileServiceClient: fileServiceClient,
		logger:            logger,
		js:                js,
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
	ext := _utils.GetFileNameExtension(req.Image.Filename)
	if ext != "jpg" && ext != "jpeg" && ext != "png" {
		return "", dto.Err_BAD_REQUEST_WRONG_EXTENTION
	}
	if req.Image.Size > constant.MAX_UPLOAD_SIZE {
		return "", dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED
	}
	ctx := context.Background()
	exist, err := a.userServiceClient.GetUserByEmail(ctx, &upb.Email{
		Email: req.Email,
	})
	if err != nil {
		code := status.Code(err)
		if code != codes.NotFound {
			a.logger.Error().Err(err).Msg("Error Query Get User By Email")
			return "", err
		}
	}
	if exist != nil {
		a.logger.Error().Str("email", req.Email).Msg("User with this email exist")
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
	imageReq := &fpb.Image{
		Image: image,
		Ext:   ext,
	}
	imageName, err := a.fileServiceClient.SaveProfileImage(ctx, imageReq)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error uploading image to file service")
		return "", err
	}
	userId := uuid.New().String()
	user := &upb.User{
		Id:       userId,
		FullName: req.FullName,
		Image:    imageName.GetName(),
		Email:    req.Email,
		Password: password,
	}
	_, err = a.userServiceClient.CreateUser(ctx, user)
	if err != nil {
		_, err := a.fileServiceClient.RemoveProfileImage(ctx, imageName)
		return "", err
	}
	token, err := jwt.GenerateToken(userId)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error JWT Signing")
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	go func() {
		sessionKey := "session:" + token
		err = a.authRepository.SetAccessToken(ctx, sessionKey, token)
		if err != nil {
			a.logger.Error().Err(err).Msg("Error saving token to Redis")
		}
	}()

	go func() {
		subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.subject.mail"), userId)
		msg := &_dto.MailNotificationMessage{
			Receiver: []string{user.Email},
			MsgType:  "welcome",
			Message:  "",
		}
		marshalledMsg, err := json.Marshal(msg)
		if err != nil {
			a.logger.Error().Err(err).Msg("marshal data error")
			return
		}
		_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
		if err != nil {
			a.logger.Error().Err(err).Msg("publish notification error")
		}

	}()
	return token, nil
}

func (a *authService) LoginService(req dto.LoginRequest) (string, error) {
	c := context.Background()
	user, err := a.userServiceClient.GetUserByEmail(c, &upb.Email{
		Email: req.Email,
	})
	if err != nil {
		a.logger.Error().Err(err).Msg("Error Query Get User By Email")
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
	sessionKey := "session:" + token
	err = a.authRepository.SetAccessToken(c, sessionKey, token)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error saving token to Redis")
		return "", dto.Err_INTERNAL_SET_TOKEN
	}
	return token, nil
}
