package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type NewReverseProxy struct {
	Route        string    `json:"route"`
	Redirect     string    `json:"redirect"`
	LocalPort    int       `json:"local_port"`
	LocalTLS     bool      `json:"local_tls"`
	TLSInsecure  bool      `json:"tls_insecure"`
	HasBasicAuth bool      `json:"has_basicauth"`
	BasicAuth    BasicAuth `json:"basicauth"`
}

type BasicAuth struct {
	Directive string `json:"directive"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type DefaultResponse struct {
	Code   int    `json:"code"`
	Detail string `json:"detail"`
}

type TokenStruct struct {
	Id      string
	Role    string
	User    string
	Expires int64
	Issuer  string
}

type DbSchema struct {
	Id         int
	Username   string
	Password   string
	Role       string
	Created_at string
}

func SendError(w http.ResponseWriter, detail string, statuscode int) {
	errormessage := DefaultResponse{
		Code:   statuscode,
		Detail: detail,
	}
	s, err := json.Marshal(errormessage)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statuscode)
	_, _ = fmt.Fprint(w, string(s))
	return
}

func RespondwithJson(w http.ResponseWriter, payload interface{}) {
	Logger.Info().Msg("Beginning Response to Request")
	response, err := json.Marshal(payload)
	if err != nil {
		Logger.Err(err).Msg("Failed Response")
		SendError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
	Logger.Info().Msg("Finished Responding")
	return
}
