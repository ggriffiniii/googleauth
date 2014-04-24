package googleauth

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"fmt"
	"github.com/gorilla/securecookie"
	"net/http"
)

type Manager struct {
	ClientId     string
	ClientSecret string
	CookieName   string
	RedirectURL  string
	key          []byte
}

type Profile struct {
	Name  string
	Email string
}

func New(clientId, clientSecret, cookieName, redirectURL string) *Manager {
	m := Manager{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		CookieName:   cookieName,
		RedirectURL:  redirectURL,
		key:          make([]byte, 64),
	}
	// Build the encryption key from the first 64 bytes of the ClientSecret.
	for i := 0; i < 64; i++ {
		m.key[i] = m.ClientSecret[i%len(m.ClientSecret)]
	}
	return &m
}

func (m *Manager) OauthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauthConf := m.getOAuthConfig()
		t := &oauth.Transport{Config: oauthConf}
		_, err := t.Exchange(r.FormValue("code"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		c := t.Client()
		resp, err := c.Get("https://www.googleapis.com/userinfo/v2/me")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		var profile Profile
		err = json.NewDecoder(resp.Body).Decode(&profile)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s := securecookie.New(m.key, m.key[:32])
		encoded, err := s.Encode(m.CookieName, profile)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		cookie := &http.Cookie{
			Name:  m.CookieName,
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, r.FormValue("state"), http.StatusFound)
	})
}

func (m *Manager) ProtectedHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := m.GetProfile(r)
		if err != nil {
			url := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
			http.Redirect(w, r, m.getOAuthConfig().AuthCodeURL(url), http.StatusFound)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (m *Manager) GetProfile(r *http.Request) (*Profile, error) {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return nil, err
	}
	s := securecookie.New(m.key, m.key[:32])
	var profile Profile
	err = s.Decode(m.CookieName, cookie.Value, &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (m *Manager) getOAuthConfig() *oauth.Config {
	return &oauth.Config{
		ClientId:     m.ClientId,
		ClientSecret: m.ClientSecret,
		Scope:        "https://www.googleapis.com/auth/userinfo.email",
		AuthURL:      "https://accounts.google.com/o/oauth2/auth",
		TokenURL:     "https://accounts.google.com/o/oauth2/token",
		RedirectURL:  m.RedirectURL,
	}
}
