package repository_test

import (
	"testing"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/dropboks/auth-service/internal/domain/repository"
	"github.com/dropboks/auth-service/test/mocks"
	"github.com/dropboks/sharedlib/model"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"
)

type GetUserByIdRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
	mockPgx         pgxmock.PgxPoolIface
}

func (g *GetUserByIdRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	pgxMock, err := pgxmock.NewPool()
	g.NoError(err)
	g.mockPgx = pgxMock
	g.mockRedisClient = redisClient
	g.authRepository = repository.New(redisClient, pgxMock, logger)
}

func (g *GetUserByIdRepositorySuite) SetupTest() {
	g.mockRedisClient.ExpectedCalls = nil
	g.mockRedisClient.Calls = nil
}

func TestGetUserByIdRepositorySuite(t *testing.T) {
	suite.Run(t, &GetUserByIdRepositorySuite{})
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_Success() {
	userId := "123"
	image := "image.png"
	expectedUser := &model.User{
		ID:               userId,
		FullName:         "John Doe",
		Image:            &image,
		Email:            "john@example.com",
		Password:         "hashedpassword",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	rows := pgxmock.NewRows([]string{
		"id", "full_name", "image", "email", "password", "verified", "two_factor_enabled",
	}).AddRow(
		expectedUser.ID,
		expectedUser.FullName,
		expectedUser.Image,
		expectedUser.Email,
		expectedUser.Password,
		expectedUser.Verified,
		expectedUser.TwoFactorEnabled,
	)

	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnRows(rows)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.NoError(err)
	g.Equal(expectedUser, user)
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_NotFound() {
	userId := "notfound"
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnError(pgx.ErrNoRows)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_NOTFOUND_USER_NOT_FOUND)
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_ScanError() {
	userId := "123"
	rows := pgxmock.NewRows([]string{
		"id", "full_name", "image", "email", "password", "verified", "two_factor_enabled",
	}).AddRow(
		123, // should be string, but using int to cause scan error
		"John Doe",
		"image.png",
		"john@example.com",
		"hashedpassword",
		true,
		false,
	)
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnRows(rows)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_INTERNAL_FAILED_SCAN_USER)
}
