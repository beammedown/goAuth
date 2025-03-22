package auth

import (
	"beammedown/goAuth/logic"
	"beammedown/goAuth/models"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/context"
)

type LoginResponse struct {
	Token string `json:"token"`
}

func isBlacklisted(token *jwt.Token, r *http.Request) bool {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jti, exists := claims["jti"]
		if !exists {
			return true
		}
		str, ok := jti.(string)
		if !ok {
			return true
		}
		_, err := GetToken(str)

		if err != nil {
			utils.Logger.Err(err).Msg("")
			return true
		}
		context.Set(r, "tokenID", str)
		return false
	}
	return true
}

func IsAuthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "" {
			authlist := strings.Split(r.Header.Get("authorization"), " ")
			if authlist[0] != "Bearer" {
				utils.Logger.Info().Msg(fmt.Sprintf("No Bearer Token provided. Instead: %v", authlist[0]))
				utils.SendError(w, "Bad Auth Header", http.StatusBadRequest)
				return
			}
			if len(authlist) != 2 {
				utils.Logger.Info().Msg(fmt.Sprintf("Badly Formatted Auth Header: %v", authlist))
				utils.SendError(w, "Bad Auth Header", http.StatusBadRequest)
				return
			}

			token, err := jwt.Parse(authlist[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				key, err := loadRSAPublicKey("public.pem")
				if err != nil {
					return nil, fmt.Errorf("Couldn't verify signature")
				}
				return key, nil
			})

			if err != nil {
				utils.Logger.Info().Msg(fmt.Sprintf("Error while checking Token: %v", err.Error()))
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			}

			switch {
			case token.Valid:
				if !isBlacklisted(token, r) {
					next.ServeHTTP(w, r)
					return
				}
				utils.Logger.Info().Msg("Token is blacklisted")
				utils.SendError(w, "Unauthorized", http.StatusUnauthorized)
				return
			case errors.Is(err, jwt.ErrTokenMalformed):
				utils.Logger.Info().Msg("Token badly formatted")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				// Invalid signature
				utils.Logger.Info().Msg("Invalid Signature")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
				// Token is either expired or not active yet
				utils.Logger.Info().Msg("Token expired or not active yet")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			default:
				utils.Logger.Info().Msg(fmt.Sprintf("Couldn't handle this token: %v", err))
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			}
		} else {
			utils.Logger.Info().Msg("No Auth Header")
			utils.SendError(w, "No Auth Provided", http.StatusBadRequest)
			return
		}
	})
}

func hasAdminRole(token *jwt.Token, r *http.Request) bool {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jti, exists := claims["jti"]
		if !exists {
			return false
		}
		jtis, ok := jti.(string)
		if !ok {
			return false
		}
		tok, err := GetToken(jtis)

		if err != nil {
			utils.Logger.Err(err).Msg("")
			return false
		}
		if tok.Role != "admin" {
			utils.Logger.Info().Msg("Tried to access without admin role")
			return false
		}
		return true
	}
	return false
}

func IsAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "" {
			authlist := strings.Split(r.Header.Get("authorization"), " ")
			if authlist[0] != "Bearer" {
				utils.Logger.Info().Msg(fmt.Sprintf("No Bearer Token provided. Instead: %v", authlist[0]))
				utils.SendError(w, "Bad Auth Header", http.StatusBadRequest)
				return
			}
			if len(authlist) != 2 {
				utils.Logger.Info().Msg(fmt.Sprintf("Badly Formatted Auth Header: %v", authlist))
				utils.SendError(w, "Bad Auth Header", http.StatusBadRequest)
				return
			}

			token, err := jwt.Parse(authlist[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				key, err := loadRSAPublicKey("public.pem")
				if err != nil {
					return nil, fmt.Errorf("Couldn't verify signature")
				}
				return key, nil
			})

			if err != nil {
				utils.Logger.Info().Msg(fmt.Sprintf("Error while checking Token: %v", err.Error()))
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			}

			switch {
			case token.Valid:
				if !isBlacklisted(token, r) && hasAdminRole(token, r) {
					next.ServeHTTP(w, r)
					return
				}
				utils.Logger.Info().Msg("Token is blacklisted")
				utils.SendError(w, "Unauthorized", http.StatusUnauthorized)
				return
			case errors.Is(err, jwt.ErrTokenMalformed):
				utils.Logger.Info().Msg("Token badly formatted")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				// Invalid signature
				utils.Logger.Info().Msg("Invalid Signature")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
				// Token is either expired or not active yet
				utils.Logger.Info().Msg("Token expired or not active yet")
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			default:
				utils.Logger.Info().Msg(fmt.Sprintf("Couldn't handle this token: %v", err))
				utils.SendError(w, "Bad Token", http.StatusBadRequest)
				return
			}
		} else {
			utils.Logger.Info().Msg("No Auth Header")
			utils.SendError(w, "No Auth Provided", http.StatusBadRequest)
			return
		}
	})
}

func Login(appy *logic.App) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			utils.SendError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		authHeader := r.Header.Get("authorization")
		if authHeader == "" {
			utils.SendError(w, "No Auth Provided", http.StatusBadRequest)
			return
		}
		autharr := strings.Split(authHeader, " ")
		if autharr[0] != "Basic" {
			utils.Logger.Debug().Msg(fmt.Sprintf("Bad Auth Header: 'authorization' %v", authHeader))
			utils.SendError(w, "Bad Auth Header", http.StatusBadRequest)
			return
		}
		authbytes, err := base64.StdEncoding.DecodeString(autharr[1])
		if err != nil {
			utils.SendError(w, "Internal Server Error", http.StatusBadRequest)
			return
		}

		authstring := string(authbytes)
		provideddata := strings.Split(authstring, ":")
		if len(provideddata) != 2 {
			utils.SendError(w, "Internal Server Error", http.StatusBadRequest)
			return
		}
		provideduser, providedpass := provideddata[0], provideddata[1]

		statement := fmt.Sprintf("SELECT * FROM Users WHERE username = '%v'", provideduser)
		res, err := appy.GetFirstResult(statement)
		if err != nil {
			utils.SendError(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if provideduser == res.Username && providedpass == res.Password {
			token, err := CreateJWT(res.Username, res.Role)
			if err != nil {
				utils.SendError(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			resp := LoginResponse{
				Token: token,
			}
			utils.RespondwithJson(w, resp)
			return
		}
		utils.SendError(w, "Login Failed", http.StatusBadRequest)
	}
}
