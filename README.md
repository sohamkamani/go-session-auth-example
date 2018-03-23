# Password authentication in Go

Read the blog post [here](https://www.sohamkamani.com/blog/2018/02/25/golang-password-authentication-and-storage/).

This repository is an implementation of simple password based authentication and storage in Go.
Passwords are stored in a Postgres DB instance.

To run the application:
- Create a postgres DB and a `users` table using the [users.sql](/sohamkamani/go-password-auth-example/blob/master/users.sql).
- Start the application with the commands: `go build` and `./go-password-auth-example`
- Test the application with the requests in the [test.http](/sohamkamani/go-password-auth-example/blob/master/test.http) file


When a user signs in to your application, their authorization has to be persisted across all other routes. In simpler words, this means that you have to know _who_ is calling your HTTP server.

One way to do this is to store the users _"session"_. A session is started once a user logs in, and expires some time after that. Each logged in user has some reference to the session, which they send with their requests. We then use this reference to look up the user that it belongs to and return information specific to them.


## Overview

In my [last post] I described how to store and authenticate your users passwords. In this post, we will look at how to store and persist the session of a logged in user, so that they can use other routes in our application.

We will build an application with a `/signin` and a `/welcome` route.

- The `/signin` route will accept a users username and password, and set a session cookie if successful.
- The `/welcome` route will be a simple HTTP `GET` route which will show a personalised message to the currently logged in user.

The session information of the user will be stored in a Redis cache. For this tutorial, we will assume that the users that are to sign in are already registered with us. 
If you want to read more on how to sign up and store password information of new users, I have written about it in my [other post]()

>If you just want to see the source code for this tutorial, you can find it [here](https://github.com/sohamkamani/go-session-auth-example)

## Creating the HTTP server

Let's start by initializing the HTTP server with the required routes and a redis connection: 

```go
import (
	"log"
	"net/http"
	"github.com/gomodule/redigo/redis"
)

// Store the redis connection as a package level variable 
var cache redis.Conn

func main() {
	initCache()
	// "Signin" and "Welcome" are the handlers that we will implement
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/welcome", Welcome)
	// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func initCache() {
	// Initialize the redis connection to a redis instance running on your local machine
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		panic(err)
	}
	// Assign the connection to the package level `cache` variable
	cache = conn
}
```

The redis connection is created and managed by the [Redigo]() library.
We can now define the `Signin` and `Welcome` routes.

## Handling user sign in

The signin route will take the users credentials and "log them in". In order to make this simple, we're storing the users information as an in-memory map in our code:

```go
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}
```

So for now, there are only two valid users in our application: `user1`, and `user2`. Next, we can write the Signin HTTP handler:

```go
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
```

If a user logs in correctly, this handler will then set a cookie on the client side, and inside its own cache.
Once a cookie is set on a client, it is sent along with every request henceforth. Now that we have persisted the clients session information on this client (in the form of the `session_token` cookie) and the server (inside our redis cache), we can write our welcome handler to handle user specific information.

## Handling post-authentication routes

Now that all logged in clients have session information stored on their end as cookies, we can use it to:

- Authenticate subsequent user requests
- Get information about the user making the request

Let's write our `Welcome` handler to do just that:

```go
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
```

From the code, we can see that our welcome handler gives us an "unauthorized" (or `401`) status under certain circumstances:
1. If there is no `session_token` cookie along with the request (which means that the requestor hasn't logged in)
2. If the session token is not present in our cache (which means that the users session has expired, or that the requestor is sending us a malicious session token)

Session based authentication keeps your users sessions secure in a couple of ways: 
1. Since the session tokens are randomly generated, an malicious user cannot guess his way into a users session.
2. Even if a users session token is compromised somehow, it cannot be used after its expiry.

One common technique that is used in conjuction with the second point is to refresh the users session token in small time intervals. So, once a user hits a "refresh" route (typically when their current token is about to expire), a new token will be issued with a renewed expiry time. The smaller this time interval, the less likely it is for any one token to compromise a users account.

## Refreshing a users session token

We can write a `Refresh` HTTP handler to refresh the users session token everytime they hit the `/refresh` route in our application

```go
func Refresh(w http.ResponseWriter, r *http.Request) {
  // (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
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
	// (END) The code uptil this point is the same as the first part of the `Welcome` route

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
```

We can now add this to the rest of our routes:

```go
http.HandleFunc("/signin", Signin)
http.HandleFunc("/welcome", Welcome)
http.HandleFunc("/refresh", Refresh)
```

## Running our application

To run this application, start a [redis server] on your local machine:

```sh
redis-server
```

Next, start the Go application:

```sh
go build
./go-session-auth-example
```

Now, using any HTTP client with support for cookies (like [Postman](https://www.getpostman.com/apps), or your web browser) make a sign-in request with the appropriate credentials:

```
POST http://localhost:8000/signin

{"username":"user2","password":"password2"}
```

You can now try hitting the welcome route from the same client to get the welcome message:

```
GET http://localhost:8000/welcome
```

Hit the refresh route, and then inspect the clients cookies to see the new value of the `session_token`:

```
POST http://localhost:8000/refresh
```

You can find the working source code for this example [here](https://github.com/sohamkamani/go-session-auth-example).
