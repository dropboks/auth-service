package jwt

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	UserId string `json:"user_id"`
	jwt.RegisteredClaims
}
