package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"beammedown/goAuth/auth"
	"beammedown/goAuth/logic"
	"beammedown/goAuth/models"

	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

func postbody(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Postit")
	return
}

func adminCheck(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Is Admin")
	return
}

func fooHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Homepage Endpoint")
	return
}

func blacklistToken(w http.ResponseWriter, r *http.Request) {
	token := context.Get(r, "tokenID")
	val, ok := token.(string)
	if !ok {
		utils.SendError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	auth.RemoveToken(val)
	w.WriteHeader(http.StatusOK)
}

func funnyfoo(w http.ResponseWriter, r *http.Request) {
	var revproxy utils.NewReverseProxy
	utils.Logger.Info().Msg("In Funny Foo")
	err := json.NewDecoder(r.Body).Decode(&revproxy)
	if err != nil {
		utils.SendError(w, "Internal Server Error", http.StatusInternalServerError)
		utils.Logger.Error().Err(err).Msg("")
		return
	}
	utils.Logger.Info().Msg("Decoded")
	err = needsReverseProxy(revproxy)
	if err != nil {
		utils.SendError(w, "Bad Request", http.StatusBadRequest)
		utils.Logger.Error().Err(err).Msg("")
		return
	}
	err = json.NewEncoder(w).Encode(revproxy)
	if err != nil {
		utils.SendError(w, "Internal Server Error", http.StatusInternalServerError)
		utils.Logger.Error().Err(err).Msg("")
		return
	}

	utils.Logger.Info().Msg("Encoded to send")
}

func needsReverseProxy(reverseproxy utils.NewReverseProxy) error {
	if reverseproxy.Route == "" {
		return errors.New("No Route given")
	}
	if reverseproxy.Redirect == "" {
		return errors.New("No Redirect given")
	}
	if reverseproxy.LocalPort == 0 {
		return errors.New("No LocalPort given")
	}
	return nil
}

func needsUserBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user utils.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			utils.SendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if user.Password == "" {
			utils.SendError(w, "No password provided", http.StatusBadRequest)
		} else if user.Username == "" {
			utils.SendError(w, "No user provided", http.StatusBadRequest)
		}
		next.ServeHTTP(w, r)
	})
}
func logthis(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		infostring := fmt.Sprintf("Getting %s Request on %s", r.Method, r.URL)
		utils.Logger.Info().Msg(infostring)
		next.ServeHTTP(w, r)
	})
}

func getCurConfig() {
	resp, err := http.Get("http://localhost:2019/config")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(resp.Body)
}

func setNewPath() {

}

func CustomNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	utils.Logger.Error().Msg("Route not Found, responding with 404")
	utils.SendError(w, "Not Found", http.StatusNotFound)
}

func handleRequests(app logic.App) {
	router := mux.NewRouter() //.StrictSlash(true)
	router.Use(logthis)

	authRouter := mux.NewRouter().PathPrefix("/api/v1/auth").Subrouter()
	authRouter.Use(logthis)

	elevatedRouter := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	elevatedRouter.Use(logthis)
	elevatedRouter.Use(auth.IsAuthorized)

	adminRouter := mux.NewRouter().PathPrefix("/api/v1/manage").Subrouter()
	adminRouter.Use(auth.IsAdmin)

	router.PathPrefix("/api/v1/auth").Handler(authRouter)
	router.PathPrefix("/api/v1/manage").Handler(adminRouter)
	router.PathPrefix("/api/v1").Handler(elevatedRouter)

	router.HandleFunc("/foo", fooHandler).Methods("GET")

	posthandler := http.HandlerFunc(postbody)
	elevatedRouter.Handle("/poster", posthandler).Methods("POST")

	loginhandler := http.HandlerFunc(auth.Login(&app))
	authRouter.Handle("/login", loginhandler).Methods("POST")

	blacklistHandler := http.HandlerFunc(blacklistToken)
	elevatedRouter.Handle("/blacklist", blacklistHandler).Methods("POST")

	funnyhandler := http.HandlerFunc(funnyfoo)
	router.Handle("/rproxy", funnyhandler)

	admintesthandler := http.HandlerFunc(adminCheck)
	adminRouter.Handle("/is", admintesthandler).Methods("POST")

	router.NotFoundHandler = http.HandlerFunc(CustomNotFoundHandler)
	elevatedRouter.NotFoundHandler = http.HandlerFunc(CustomNotFoundHandler)
	authRouter.NotFoundHandler = http.HandlerFunc(CustomNotFoundHandler)

	utils.Logger.Info().Msg("Initialized Information")
	utils.Logger.Info().Msg("Running on Port 8001")
	utils.Logger.Fatal().Err(http.ListenAndServe(":8001", router)).Msg("")
}
func test_setup() {
	file, err := os.OpenFile("test_logs.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		utils.Logger.Error().Err(err).Msg("")
	}
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	utils.Logger = zerolog.New(file).With().Timestamp().Caller().Logger()
	utils.Logger.Info().Msg("Setting up .env")
	err = godotenv.Load()
	if err != nil {
		utils.Logger.Error().Err(err).Msg("Error loading .env")
	}
	utils.Logger.Info().Msg("Done")
}
func main() {
	utils.SetupLogger()
	app := logic.App{}
	err := app.InitDB()
	if err != nil {
		utils.Logger.Err(err).Msg("")
		os.Exit(1)
	}
	err = app.AddUser("someone", "passing", "user")
	if err != nil {
		utils.Logger.Err(err).Msg("")
		os.Exit(1)
	}
	defer app.DB.Close()

	handleRequests(app)
}
