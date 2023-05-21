package main

import (
	// "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func get_authcode(r *http.Request) string {
	cookies := r.Cookies()
	var authcode string
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == "authcode" {
			fmt.Println(cookies[i].Value)
			authcode = cookies[i].Value
		}
	}

	return authcode
}

// TODO: check this makes sense to have
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func toJsonString(thing interface{}) string {
	ret, err := json.Marshal(thing)
	if err != nil {
		fmt.Println("error formatting json")
	}

	return strings.ToLower(string(ret))
}

func requestPathToStrings(r *http.Request) []string {
	return strings.Split(r.URL.Path, "/")[2:]
}

// array of accounts
// store passwords in encrypted hash format
// load posts from file
// array of posts

// file with used codes
// file with available codes

type ActiveUser struct {
	Name     string
	IsAdmin  bool
	Authcode string
}

var active_users []ActiveUser

func salt_and_hash(salt string, password string, username string) string {
	// h := sha512.New()
	// h.Write([]byte(password))
	// h.Write([]byte(username))
	// s := h.Sum([]byte(salt))

	return password
}

var POSSIBLE_ID_CHARACTERS = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")

func gen_rand_id(length int) string {
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		bytes[i] = POSSIBLE_ID_CHARACTERS[rand.Intn(len(POSSIBLE_ID_CHARACTERS))]
	}

	return string(bytes[:length])
}

func get_user_from_authcode(authcode string) (ActiveUser, error) {
	if len(authcode) < 128 {
		return ActiveUser{}, errors.New("Invalid authcode")
	}

	for i := 0; i < len(active_users); i++ {
		if active_users[i].Authcode == authcode {
			return active_users[i], nil
		}
	}
	return ActiveUser{}, errors.New("Invalid authcode")
}

func user_login(in_username string, in_password string) (user ActiveUser, error error) {
	// open accounts  file
	a_bytes, _ := ioutil.ReadFile("accounts.csv")
	a_string := string(a_bytes)
	rows := strings.Split(a_string, "\n") // ignore header bit of the csv
	rows = rows[1 : len(rows)-1]

	for i := 0; i < len(rows); i++ {
		row := rows[i]
		cols := strings.Split(row, ",")

		// csv format:  name,password,salt,is_admin,register_code
		name := cols[0]
		hashed_password := cols[1]
		salt := cols[2]
		is_admin := cols[3]

		fmt.Println("comparing usernames:", in_username, "and", name)

		if in_username == name {
			// check password
			h := salt_and_hash(salt, in_password, in_username)
			if h == hashed_password {
				// user is verified
				var u ActiveUser
				u.Name = name
				u.IsAdmin = (is_admin == "yes")

				// generate a random unique cookie
				u.Authcode = gen_rand_id(128)
				unique := false
				for !unique {
					unique = true
					for i := 0; i < len(active_users); i++ {
						if active_users[i].Authcode == u.Authcode {
							unique = false
							u.Authcode = gen_rand_id(128)
						}
					}
				}

				fmt.Println("found user, made id: ", u.Authcode)

				return u, nil
			} else {
				// not verified wrong password
				return ActiveUser{}, errors.New("Wrong password")
			}
		}
	}

	// on success add active user +
	// on fail send error message
	return ActiveUser{}, errors.New("Wrong username")
}

func main() {

	_, err := user_login("richard", "password")
	if err != nil {
		fmt.Println(err)
	}

	head, err := ioutil.ReadFile("templates/head.html")
	if err != nil {
		fmt.Println("no head file!")
	}
	tail, err := ioutil.ReadFile("templates/tail.html")
	if err != nil {
		fmt.Println("no tail file!")
	}

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		body, _ := ioutil.ReadFile("templates/index.html")
		w.Write(head)
		w.Write(body)
		w.Write(tail)
	})

	http.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		body, _ := ioutil.ReadFile("templates/about.html")
		w.Write(head)
		w.Write(body)
		w.Write(tail)
	})

	http.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		body, _ := ioutil.ReadFile("templates/login.html")
		w.Write(head)
		w.Write(body)
		w.Write(tail)
	})

	http.HandleFunc("/logintry", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		success_page, _ := ioutil.ReadFile("templates/success.html")
		fail_page, _ := ioutil.ReadFile("templates/fail.html")

		r.ParseForm()
		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")

		user, err := user_login(username, password)

		if err != nil {
			w.Write(fail_page)
		} else {
			// if logged in send cookie
			c := http.Cookie{Name: "authcode", Value: user.Authcode, Expires: time.Now().Add(6 * time.Hour)}
			c.SameSite = http.SameSiteStrictMode
			http.SetCookie(w, &c)
			active_users = append(active_users, user)

			// show succesful login page
			// fmt.Fprintln(w, "success check cookies")
			w.Write(success_page)
		}
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := get_authcode(r)
		user, err := get_user_from_authcode(authcode)

		if err != nil {
			// invalid but not possible in ui so do nothing
		} else {
			// user is logged in and wants to sign out

			c := http.Cookie{Name: "authcode", Value: "", Expires: time.Now().Add(6 * time.Hour)}
			c.SameSite = http.SameSiteStrictMode
			http.SetCookie(w, &c)

			for i := 0; i < len(active_users); i++ {
				u := active_users[i]
				if u == user {
					// replace current user with last user
					active_users[i] = active_users[len(active_users)-1]

					// remove the last user "deleting" it from array
					active_users = active_users[:len(active_users)-1]

					break
				}
			}

			body, _ := ioutil.ReadFile("templates/index.html")
			w.Write(head)
			w.Write(body)
			w.Write(tail)
		}
	})
	http.HandleFunc("/ui-loginbutton", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := get_authcode(r)
		user, err := get_user_from_authcode(authcode)

		if err != nil {
			fmt.Fprintf(w, "<a href=\"/login\" class=\"nav-item\">LOGIN</a>")
		} else {
			if user.IsAdmin {
				fmt.Fprintf(w, "<a href=\"/admin\" class=\"nav-item\">ADMIN</a>")
			}
			fmt.Fprintf(w, "<a href=\"/logout\" class=\"nav-item\">LOGOUT</a>")
		}
	})

	port := "9696"
	fmt.Println("Starting server...\n\tPort:\t\t", port, "\n\tUnix time:\t", time.Now().Unix())

	err = http.ListenAndServeTLS(":"+string(port), "certs/cert.pem", "certs/key.pem", nil)
	fmt.Println(err)
}
