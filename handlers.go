package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/satori/go.uuid"
)

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func Signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the expected password from our in memory map
	expectedPassword, ok := users[creds.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Create a new random session token
	sessionToken := uuid.NewV4().String()
	// Set the token in the cache, along with the user whom it represents
	// The token has an expiry time of 120 seconds
	_, err = cache.Do("SETEX", sessionToken, "120", creds.Username)
	if err != nil {
		// If there is an error in setting the cache, return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Finally, we set the client cookie for "session_token" as the session token we just generated
	// we also set an expiry time of 120 seconds, the same as the cache
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(120 * time.Second),
	})
}

func Welcome(w http.ResponseWriter, r *http.Request) {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	// We then get the name of the user from our cache, where we set the session token
	response, err := cache.Do("GET", sessionToken)
	if err != nil {
		// If there is an error fetching from cache, return an internal server error status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if response == nil {
		// If the session token is not present in cache, return an unauthorized error
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Finally, return the welcome message to the user
	w.Write([]byte(fmt.Sprintf("Welcome %s!", response)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value

	response, err := cache.Do("GET", sessionToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if response == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// The code uptil this point is the same as the first part of the `Welcome` route

	// Now, create a new session token for the current user
	newSessionToken := uuid.NewV4().String()
	_, err = cache.Do("SETEX", newSessionToken, "120", fmt.Sprintf("%s",response))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete the older session token
	_, err = cache.Do("DEL", sessionToken)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	
	// Set the new token as the users `session_token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   newSessionToken,
		Expires: time.Now().Add(120 * time.Second),
	})
}