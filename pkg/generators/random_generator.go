package generators

import (
	_utils "github.com/dropboks/sharedlib/utils"
	"github.com/google/uuid"
)

type (
	RandomGenerator interface {
		GenerateUUID() string
		GenerateToken() (string, error)
	}
	randomGenerator struct{}
)

func NewRandomStringGenerator() RandomGenerator {
	return &randomGenerator{}
}

func (g *randomGenerator) GenerateUUID() string {
	return uuid.New().String()
}

func (g *randomGenerator) GenerateToken() (string, error) {
	return _utils.RandomString64()
}
