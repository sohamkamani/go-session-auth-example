---
layout: post
title: Password authentication and storage in Go (Golang) 🔑
date: 2018-02-25T01:45:12.000Z
categories: go golang
description: "This post demonstrates how to sign up and sign in users using password authentication in Go"
comments: true
---

Any application that involves password storage and authentication has to make sure that its password are safely stored. You cannot simply store the username and password of your users the way you store other types of data. In fact, it should be impossible for you to actually _know_ the password of any of your users.

This post will go through how to securely store your users password by building a very simple web application in Go, and using a Postgres database to store your users credentials.

## Overview

We are going to build a simple HTTP server with two routes: `/signup` and `/signin`, and use a Postgres DB to store user credentials.

- `/signup` will accept user credentials, and securely store them in our database.
- `/signin` will accept user credentials, and authenticate them by comparing them with the entries in the database.

We will be using the [bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt) algorithm to hash and salt our passwords. If want to know more about hashing, salting, and the theory behind secure password storage, you can read my [previous post](https://godoc.org/golang.org/x/crypto/bcrypt).

## Initializing the web application

Before we implement password storage, let's create our database and initialize our HTTP server:

### Creating our database

Make a new database in postgres using the `createdb` command:

```sh
createdb mydb
```

Connect to the database:

```sh
psql mydb
```

Then, create the `users` table, with the `username` and `password` columns:

```sql
create table users (
  username text primary key,
  password text
);
```

### Initializing the HTTP server

```go
// The "db" package level variable will hold the reference to our database instance
var db *sql.DB

func main() {
	// "Signin" and "Signup" are handler that we will implement
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/signup", Signup)
	// initialize our database connection
	initDB()
	// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func initDB(){
	var err error
	// Connect to the postgres db
	//you might have to change the connection string to add your database credentials
	db, err = sql.Open("postgres", "dbname=mydb sslmode=disable")
	if err != nil {
		panic(err)
	}
}
```

## Implementing user sign up

In order to create a user, or sign them up, we will make a handler that accepts a `POST` request, with a JSON body of the form:

```json
{
  "username": "johndoe",
  "password": "mysecurepassword"
}
```

The handler will return a `200` status if the user has been signed up successfully:

```go
// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password", db:"password"`
	Username string `json:"username", db:"username"`
}

func Signup(w http.ResponseWriter, r *http.Request){
	// Parse and decode the request body into a new `Credentials` instance
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status
		w.WriteHeader(http.StatusBadRequest)
		return 
	}
	// Salt and hash the password using the bcrypt algorithm
	// The second argument is the cost of hashing, which we arbitrarily set as 8 (this value can be more or less, depending on the computing power you wish to utilize)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)

	// Next, insert the username, along with the hashed password into the database
	if _, err = db.Query("insert into users values ($1, $2)", creds.Username, string(hashedPassword)); err != nil {
		// If there is any issue with inserting into the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// We reach this point if the credentials we correctly stored in the database, and the default status of 200 is sent back
}
```

At this point, we can start the server and attempt to send a request to store some credentials:

```
POST http://localhost:8000/signup

{
  "username": "johndoe",
  "password": "mysecurepassword"
}
```

If we inspect our database now, we can see that the password field does not contain the password that we sent just now:

```
mydb=# select * from users;
 username |                           password
----------+--------------------------------------------------------------
 johndoe  | $2a$08$2AH4glNU51oZY0fRMyhc7e/HyCG5.n37mqmuYdJnWiKMBcq1aXNtu
(1 row)
```

Once a password is hashed with bcrypt, there is no way we can reverse the hash. Essentially, we cannot know the password of our own users, even though we have full access to the `users` table.

## Implementing user login

We now have to create a handler that will authenticate a user given his username and password, against the entries in our database.

```go
func Signin(w http.ResponseWriter, r *http.Request){
	// Parse and decode the request body into a new `Credentials` instance	
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// If there is something wrong with the request body, return a 400 status		
		w.WriteHeader(http.StatusBadRequest)
		return 
	}
	// Get the existing entry present in the database for the given username
	result := db.QueryRow("select password from users where username=$1", creds.Username)
	if err != nil {
		// If there is an issue with the database, return a 500 error
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// We create another instance of `Credentials` to store the credentials we get from the database
	storedCreds := &Credentials{}
	// Store the obtained password in `storedCreds`
	err = result.Scan(&storedCreds.Password)
	if err != nil {
		// If an entry with the username does not exist, send an "Unauthorized"(401) status
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// If the error is of any other type, send a 500 status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Compare the stored hashed password, with the hashed version of the password that was received
	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		// If the two passwords don't match, return a 401 status
		w.WriteHeader(http.StatusUnauthorized)
	}

	// If we reach this point, that means the users password was correct, and that they are authorized
	// The default 200 status is sent
}
```

Now, we can try to log in by making a `POST` request to the `/signin` route:

```
POST http://localhost:8000/signin

{
  "username": "johndoe",
  "password": "mysecurepassword"
}
```

this will give you a `200` status code. If we make a request with an incorrect password, or with a username that does not exist, we'll get a `401` status code:

```
POST http://localhost:8000/signin

{
  "username": "johndoe",
  "password": "incorrect"
}
```

If you want to run a working version of the server, you can view the source code [here <i class="fa fa-github"></i>](https://github.com/sohamkamani/go-password-auth-example)