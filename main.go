package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aodin/volta/auth"
	"github.com/aodin/volta/config"
	"github.com/codegangsta/envy/lib"
	"golang.org/x/oauth2"
)

func ParseConfig() *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     os.Getenv("MEMBERS_CLIENT_ID"),
		ClientSecret: os.Getenv("MEMBERS_CLIENT_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("MEMBERS_AUTH_URL"),
			TokenURL: os.Getenv("MEMBERS_TOKEN_URL"),
		},
		RedirectURL: os.Getenv("MEMBERS_REDIRECT_URL"),
		Scopes:      []string{}, // TODO pull from environment
	}

	if c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		log.Panic("Invalid oauth2 config", c)
	}
	return c
}

type server struct {
	oauthConfig *oauth2.Config
	sessions    map[string]*oauth2.Token // session key : oauth token
}

func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// TODO validate state in a crypto secure manner

	// Set an auth token
	token, err := s.oauthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// TODO pull from the /me endpoint to populate session information
	log.Println("creating session token")

	// Set the cookie
	session := auth.Session{
		Key:     auth.RandomKey(),
		Expires: time.Now().AddDate(4, 0, 0),
	}
	auth.SetCookie(w, config.DefaultCookie, session)

	// Create a new session key and save it to match the token
	s.sessions[session.Key] = token

	// Redirect to home!
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (s *server) SessionRequired(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie(config.DefaultCookie.Name)
		if err != nil {
			session = &http.Cookie{}
		}
		if _, ok := s.sessions[session.Value]; !ok {
			// TODO generate a random state
			url := s.oauthConfig.AuthCodeURL("state?")
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		f(w, r)
	}
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	// Get the oauth token from the sessions
	session, _ := r.Cookie(config.DefaultCookie.Name)
	token := s.sessions[session.Value]

	req, err := http.NewRequest("GET", "http://localhost:3000/api/v2/me", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Create a bearer request using the given token
	// TODO TODO Attach extra info?
	token.SetAuthHeader(req)

	client := oauth2.NewClient(oauth2.NoContext, nil)
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	me := map[string]interface{}{}
	if err = json.NewDecoder(resp.Body).Decode(&me); err != nil {
		http.Error(w, err.Error(), 500)
	}

	w.Write([]byte(fmt.Sprintf(
		"response (%d): %s", resp.StatusCode, time.Now().UTC(),
	)))

	pretty, _ := json.MarshalIndent(me, "", "  ")
	w.Write(pretty)
}

func NewServer() *server {
	return &server{
		oauthConfig: ParseConfig(),
		sessions:    make(map[string]*oauth2.Token),
	}
}

func main() {
	// Bootstrap the environment
	envy.Bootstrap()

	// TODO parse a volta config

	// Create a new server
	s := NewServer()

	// Create the test server
	http.HandleFunc("/callback", s.callback)
	http.HandleFunc("/", s.SessionRequired(s.root))
	log.Println("Starting server on :8008")
	log.Fatal(http.ListenAndServe(":8008", nil))
}
