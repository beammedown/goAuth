package auth

import (
	utils "beammedown/goAuth/models"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwts = make(map[string]utils.TokenStruct)

func GetToken(id string) (utils.TokenStruct, error) {
	val, ok := jwts[id]
	if ok {
		return val, nil
	}
	return utils.TokenStruct{}, errors.New("No Token with this ID registered")
}

func SetToken(id string, content utils.TokenStruct) {
	utils.Logger.Info().Msg("Adding Item to jwts Map")
	jwts[string(id)] = content
	utils.Logger.Info().Msg("Finished adding Item")
}
func RemoveToken(id string) {
	delete(jwts, id)
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(keyBytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func CreateJWT(username string, role string) (string, error) {
	key, err := loadRSAPrivateKey("private.pem")
	if err != nil {
		return "", err
	}
	user := username
	expires := time.Now().Unix() + 3600

	hasher := sha256.New()
	nowUnix := fmt.Sprintf("%x", time.Now().Unix())
	hasher.Write([]byte(nowUnix))
	token_id := hex.EncodeToString(hasher.Sum(nil))

	t := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"iss": "caddymanager",
			"sub": user,
			"exp": expires,
			"jti": token_id,
			"rol": role,
		})

	s, err := t.SignedString(key)
	if err != nil {
		utils.Logger.Error().Err(err).Msg("Error signing JWT")
		return "", err
	}
	SetToken(token_id, utils.TokenStruct{
		Id:      token_id,
		Expires: expires,
		Issuer:  "caddymanager",
		User:    user,
		Role:    role,
	})
	return s, nil
}
