package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	netUrl "net/url"
	"regexp"
	"runtime"
	"strings"

	"github.com/corneldamian/httpway"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kataras/hcaptcha"
	"golang.org/x/crypto/bcrypt"
)

var errAlreadySetUp = errors.New("already set up")
var errLinkExists = errors.New("short link already exists")
var errInvalidShortLink = errors.New("short link invalid")
var errCaptchaFailed = errors.New("captcha failed")
var errInvalidParams = errors.New("invalid parameters")
var errUnauthorized = errors.New("unauthorized")

var captchaClient *hcaptcha.Client
var server *httpway.Server

var symbolsRegEx = regexp.MustCompile("[^a-zA-Z0-9]+")

var invalidWords = []string{"login", "logout", "new", "setup", "preview", "delete"}

func main() {
	configure()
	prepareSessionKey()
	initializeDatabase()
	defer deinitializeDatabase()

	captchaClient = hcaptcha.New(config.Captcha.HCaptchaSecretKey)

	captchaClient.FailureHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, errCaptchaFailed, http.StatusTooManyRequests)
	})

	r := mux.NewRouter()

	r.HandleFunc("/", index).Methods("GET")
	r.Handle("/login", captchaClient.Handler(http.HandlerFunc(login))).Methods("POST")
	r.HandleFunc("/logout", logout).Methods("POST")
	r.HandleFunc("/new", create).Methods("POST")
	r.HandleFunc("/setup", setup).Methods("GET")
	r.Handle("/setup", captchaClient.Handler(http.HandlerFunc(submitSetup))).Methods("POST")
	r.HandleFunc("/preview/{key}", preview).Methods("GET")
	r.HandleFunc("/delete/{key}", confirmDelete).Methods("GET")
	r.HandleFunc("/delete/{key}", delete)
	r.HandleFunc("/{key}", link).Methods("GET")

	log.Fatal(http.ListenAndServe(config.Server.Address, r))
}

func setup(w http.ResponseWriter, r *http.Request) {
	templates["setup"].Execute(w, setupPageData{
		HCaptchaSiteKey: config.Captcha.HCaptchaSiteKey,
	})
}

func submitSetup(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("username") == "" || r.FormValue("password") == "" {
		writeError(w, errInvalidParams, http.StatusBadRequest)
		return
	}

	_, ok := hcaptcha.Get(r)

	if !ok {
		writeError(w, errCaptchaFailed, http.StatusTooManyRequests)
		return
	}

	userCount := 0

	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	if userCount != 0 {
		writeError(w, errAlreadySetUp, http.StatusBadRequest)
		return
	}

	hashedPw, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", r.FormValue("username"), string(hashedPw))
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	userID := 0
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", r.FormValue("username")).Scan(&userID)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = userID
	err = session.Save(r, w)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)

}

func isLoggedIn(session *sessions.Session) bool {
	return session.Values["userID"] != nil && session.Values["userID"] != 0
}

func index(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	fmt.Println(session.Values["userID"])

	if isLoggedIn(session) {
		rows, err := db.Query("SELECT id, short, url, clicks FROM links WHERE ownerId = ? ORDER BY id DESC", session.Values["userID"])
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		links := []shortenedLink{}
		for rows.Next() {
			link := shortenedLink{}
			rows.Scan(&link.ID, &link.Key, &link.URL, &link.Clicks)
			links = append(links, link)
		}
		templates["home"].Execute(w, homePageData{
			Links: links,
		})
	} else {
		templates["login"].Execute(w, loginPageData{
			HCaptchaSiteKey: config.Captcha.HCaptchaSiteKey,
		})
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("username") == "" || r.FormValue("password") == "" {
		writeError(w, errInvalidParams, http.StatusInternalServerError)
		return
	}

	_, ok := hcaptcha.Get(r)

	if !ok {
		writeError(w, errCaptchaFailed, http.StatusTooManyRequests)
		return
	}

	password := ""
	id := 0

	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", r.FormValue("username")).Scan(&id, &password)
	if err == sql.ErrNoRows {
		templates["login"].Execute(w, loginPageData{
			HCaptchaSiteKey: config.Captcha.HCaptchaSiteKey,
			ShowError:       true,
			Error:           "Invalid username or password.",
		})
		return
	} else if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	passwordInvalidErr := bcrypt.CompareHashAndPassword([]byte(password), []byte(r.FormValue("password")))
	if passwordInvalidErr != nil {
		templates["login"].Execute(w, loginPageData{
			HCaptchaSiteKey: config.Captcha.HCaptchaSiteKey,
			ShowError:       true,
			Error:           "Invalid username or password.",
		})
		return
	}

	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = id
	err = session.Save(r, w)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)

}

func logout(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = 0
	err = session.Save(r, w)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func create(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	if !isLoggedIn(session) {
		writeError(w, errUnauthorized, http.StatusUnauthorized)
		return
	}

	if r.FormValue("key") == "" || r.FormValue("url") == "" {
		writeError(w, errInvalidParams, http.StatusBadRequest)
		return
	}

	normalizedKey := strings.ToLower(symbolsRegEx.ReplaceAllString(r.FormValue("key"), ""))

	_, err = netUrl.ParseRequestURI(r.FormValue("url"))
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	if contains(invalidWords, normalizedKey) {
		writeError(w, errInvalidShortLink, http.StatusBadRequest)
		return
	}

	id := 0

	found := db.QueryRow("SELECT id FROM links WHERE short = ?", normalizedKey).Scan(&id)

	if found == nil {
		writeError(w, errLinkExists, http.StatusBadRequest)
		return
	} else if found != sql.ErrNoRows {
		writeError(w, found, http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO links (short, url, ownerId, clicks) VALUES (?, ?, ?, ?)", normalizedKey, r.FormValue("url"), session.Values["userID"], 0)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func link(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := strings.ToLower(vars["key"])

	url := ""
	clicks := 0

	err := db.QueryRow("SELECT url, clicks FROM links WHERE short = ?", key).Scan(&url, &clicks)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		templates["notfound"].Execute(w, nil)
		return
	} else if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	clicks++

	_, err = db.Exec("UPDATE links SET clicks = ? WHERE short = ?", clicks, key)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func preview(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := strings.ToLower(vars["key"])

	url := ""
	clicks := 0

	err := db.QueryRow("SELECT url, clicks FROM links WHERE short = ?", key).Scan(&url, &clicks)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		templates["notfound"].Execute(w, nil)
		return
	} else if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	clicks++

	_, err = db.Exec("UPDATE links SET clicks = ? WHERE short = ?", clicks, key)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
	templates["preview"].Execute(w, previewPageData{
		Key: key,
		URL: url,
	})
}

func delete(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	if !isLoggedIn(session) {
		writeError(w, errUnauthorized, http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	key := vars["key"]

	_, err = db.Exec("DELETE FROM links WHERE short = ?", key)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func confirmDelete(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session")
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	if !isLoggedIn(session) {
		writeError(w, errUnauthorized, http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	key := vars["key"]

	templates["delete"].Execute(w, deleteData{key})
}

func writeError(w http.ResponseWriter, err error, status int) {
	w.WriteHeader(status)

	errorData := errorPageData{}

	errorData.Error = err.Error()

	buf := make([]byte, 1<<16)
	stackSize := runtime.Stack(buf, false)
	stackTrace := string(buf[0:stackSize])

	errorData.StackTrace = stackTrace

	templates["error"].Execute(w, errorData)
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
