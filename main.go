package main

import (
	"log"
	"net/http"
	"github.com/gomodule/redigo/redis"
)

var cache redis.Conn

func main() {
	initCache()
	// "Signin" and "Signup" are handler that we will implement
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", Welcome)
	http.HandleFunc("/refresh", Refresh)
	// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func initCache() {
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		panic(err)
	}
	cache = conn
}
