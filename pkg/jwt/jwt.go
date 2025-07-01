package jwt

import (
	"time"

	"github.com/dropboks/auth-service/internal/domain/dto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

func GenerateToken(userId string, timeDuration time.Duration) (string, error) {
	jwtKey := []byte(viper.GetString("jwt.secret_key"))
	var expirationTime *jwt.NumericDate
	if timeDuration > 0 {
		expirationTime = jwt.NewNumericDate(time.Now().Add(timeDuration))
	}

	claims := &Claims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expirationTime,
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
