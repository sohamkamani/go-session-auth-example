package main

import (
	"log"
	"net/http"
)

func main() {
	// "Signin" and "Signup" are handlers that we have to implement
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)
	http.HandleFunc("/logout", Logout)
	// start the server on port 8080
	log.Fatal(http.ListenAndServe(":8080", nil))
}
