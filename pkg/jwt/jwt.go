package jwt

import (
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

func GenerateToken(userId string) (string, error) {
	jwtKey := []byte(viper.GetString("jwt.secret_key"))
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    viper.GetString("app.name"),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func ValidateJWT(tokenStr string) (*Claims, error) {
	jwtKey := []byte(viper.GetString("jwt.secret_key"))
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, dto.Err_UNAUTHORIZED_JWT_INVALID
	}
	return claims, nil
}
