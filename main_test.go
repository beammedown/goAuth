package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gobackend/auth"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// TODO: Test what happens if different Bodys and so on are sent
func TestLoginGeneral(t *testing.T) {

	t.Run("return everythin working", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, "/login", nil)
		encodedcred := base64.StdEncoding.EncodeToString([]byte("admin:wonderwall"))
		request.Header.Set("authorization", fmt.Sprintf("Basic %v", encodedcred))

		response := httptest.NewRecorder()

		test_setup()
		auth.Login(response, request)

		got := response.Body.String()
		want := regexp.MustCompile(`^\{\s*"token"\s*:\s*".*"\s*\}\s*$`)
		if !want.MatchString(got) {
			t.Errorf("got no regex Match for %q in %q", want, got)
		}
	})
	t.Run("Request with GET", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
		encodedcred := base64.StdEncoding.EncodeToString([]byte("admin:wonderwall"))
		request.Header.Set("authorization", fmt.Sprintf("Basic %v", encodedcred))

		response := httptest.NewRecorder()

		test_setup()
		login(response, request)

		if !(response.Result().StatusCode == 405) {
			t.Errorf("Server responded with: %v instead of %v", response.Result().StatusCode, 405)
		}
	})
	t.Run("Send invalid Credentials", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		encodedcred := base64.StdEncoding.EncodeToString([]byte("admin:wonderwll"))
		request.Header.Set("authorization", fmt.Sprintf("Basic %v", encodedcred))

		response := httptest.NewRecorder()

		test_setup()
		login(response, request)

		got := response.Body.String()
		want := "{\"code\":400,\"detail\":\"Login Failed\"}\n"
		if got != want || response.Result().StatusCode != 400 {
			t.Errorf("got %q but wanted %q", got, want)
		}

	})
	t.Run("Send badly formatted Header", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		encodedcred := base64.StdEncoding.EncodeToString([]byte("admin:wonderwall"))
		request.Header.Set("authorization", fmt.Sprintf("%v", encodedcred))

		response := httptest.NewRecorder()

		test_setup()
		login(response, request)

		got := response.Body.String()
		want := "{\"code\":400,\"detail\":\"Bad Auth Header\"}\n"
		if got != want || response.Result().StatusCode != 400 {
			t.Errorf("got %q but wanted %q with code %v", got, want, response.Result().StatusCode)
		}
	})
	// TODO: Implement this
	t.Run("Send Bearer Token to login", func(t *testing.T) {

	})
}

func TestAuthMiddleware(t *testing.T) {
	t.Run("Get Poster with Auth", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		encodedcred := base64.StdEncoding.EncodeToString([]byte("admin:wonderwall"))
		request.Header.Set("authorization", fmt.Sprintf("Basic %v", encodedcred))

		response := httptest.NewRecorder()

		test_setup()
		login(response, request)

		if response.Result().StatusCode != 200 {
			t.Errorf("/login returned %v but wanted Code 200", response.Result().StatusCode)
		}
		jwt_map := make(map[string]string)

		jwt := response.Body.Bytes()

		if err := json.Unmarshal(jwt, &jwt_map); err != nil {
			t.Errorf("Couldn't unmarshal Body of /login: %v", response.Body.String())
		}
		posthandler := http.HandlerFunc(postbody)
		middleware := isAuthorized(posthandler)

		request, _ = http.NewRequest(http.MethodPost, "/poster", nil)
		request.Header.Set("authorization", fmt.Sprintf("Bearer %v", jwt_map["token"]))

		response = httptest.NewRecorder()

		middleware.ServeHTTP(response, request)

		if response.Result().StatusCode != 200 {
			t.Errorf("Wanted Code 200, got %v", response.Result().StatusCode)
		}
	})
}
func TestFoo(t *testing.T) {
	expected := "Homepage Endpoint"

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	w := httptest.NewRecorder()

	fooHandler(w, req)

	res := w.Result()

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)

	if err != nil {
		t.Errorf(`Error: %v`, err)
	}
	if string(data) != expected {
		t.Errorf(`/foo = %q, want %v`, data, expected)
	}
}
