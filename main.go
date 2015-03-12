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

// server holds the oauth config and session map
type server struct {
	config      config.Config
	oauthConfig *oauth2.Config
	sessions    map[string]*oauth2.Token // session key : oauth token
}

// SessionRequired wraps the root handler. It checks that the client has a
// valid session on the test application.
func (s *server) SessionRequired(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie(config.DefaultCookie.Name)
		if err != nil {
			session = &http.Cookie{}
		}
		if _, ok := s.sessions[session.Value]; !ok {
			// prompt to signin
			w.Write([]byte(`<a href="/signin">Sign-in</a>`))
			return
		}
		f(w, r)
	}
}

// callback is hit when the user has successfully authenticated on the
// oauth2 provider
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// TODO state should be persisted for the session
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

	// TODO cookie name should come from the volta config
	auth.SetCookie(w, config.DefaultCookie, session)

	// Create a new session key and save it to match the token
	s.sessions[session.Key] = token

	// Redirect to home!
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// root handler will proxy a call the v2 me endpoint
func (s *server) root(w http.ResponseWriter, r *http.Request) {
	// Get the oauth token from the sessions
	// TODO cookie name should come from the volta config
	cookieName := config.DefaultCookie.Name
	session, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "Failed to find session cookie "+cookieName, 401)
		return
	}

	// Exchange the session value for an oauth2 token
	token := s.sessions[session.Value]

	// Create the proxy URI
	uri := os.Getenv("OAUTH_URL") + "/api/v2/me"

	// Create a new request to a protect resource
	req, err := http.NewRequest("GET", uri, nil)
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
		return
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

func (s *server) signin(w http.ResponseWriter, r *http.Request) {
	// TODO generate a random state
	url := s.oauthConfig.AuthCodeURL("state?")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	return
}

func (s *server) signout(w http.ResponseWriter, r *http.Request) {
	// Get the oauth token from the sessions
	// TODO cookie name should come from the volta config
	cookieName := config.DefaultCookie.Name
	session, err := r.Cookie(cookieName)
	if err != nil || session == nil {
		w.Write([]byte("no session exists"))
		return
	}

	delete(s.sessions, session.Value)
	w.Write([]byte(fmt.Sprintf("<p>signed out of session %s</p>", session.Name)))
	w.Write([]byte(`<p><a href="/">Home</a></p>`))
}

// NewServer creates a new server by parsing an oauth2 config and initializing
// a sessions map
func NewServer() *server {
	return &server{
		oauthConfig: ParseConfig(),
		sessions:    make(map[string]*oauth2.Token),
	}
}

// ParseConfig builds an oauth2 config from environmental variables
func ParseConfig() *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     os.Getenv("OAUTH_ID"),
		ClientSecret: os.Getenv("OAUTH_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("OAUTH_URL") + "/accounts/authorize",
			TokenURL: os.Getenv("OAUTH_URL") + "/accounts/token",
		},
		RedirectURL: os.Getenv("CALLBACK_URL"),
		Scopes:      []string{}, // TODO pull from environment
	}

	if c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		log.Panic("Invalid oauth2 config", c)
	}
	return c
}

func main() {
	// Bootstrap the environment
	envy.Bootstrap()

	// Create a new server
	// TODO Parse a volta config
	s := NewServer()

	port := os.Getenv("PORT")

	// Create the test server
	http.HandleFunc("/callback", s.callback)
	http.HandleFunc("/signin", s.signin)
	http.HandleFunc("/signout", s.signout)
	http.HandleFunc("/", s.SessionRequired(s.root))
	log.Printf("Starting server on :%s\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
