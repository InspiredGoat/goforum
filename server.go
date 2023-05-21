package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func authcode_from_request(r *http.Request) string {
	cookies := r.Cookies()
	var authcode string
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == "authcode" {
			// fmt.Println(cookies[i].Value)
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

type User struct {
	Name     string
	IsAdmin  bool
	Authcode string
}

var active_users []User

func salt_and_hash(salt string, password string, username string) string {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte(username))
	s := h.Sum([]byte(salt))

	return base64.StdEncoding.EncodeToString(s)
}

var POSSIBLE_ID_CHARACTERS = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")

func base64_random(length int) string {
	bytes := make([]byte, length)

	for i := 0; i < length; i++ {
		bytes[i] = POSSIBLE_ID_CHARACTERS[rand.Intn(len(POSSIBLE_ID_CHARACTERS))]
	}

	return string(bytes[:length])
}

func user_from_authcode(authcode string) (User, error) {
	if len(authcode) < 128 {
		return User{}, errors.New("Invalid authcode")
	}

	for i := 0; i < len(active_users); i++ {
		if active_users[i].Authcode == authcode {
			return active_users[i], nil
		}
	}
	return User{}, errors.New("Invalid authcode")
}

func file_lines(filename string) []string {
	a_bytes, _ := ioutil.ReadFile(filename)
	a_string := string(a_bytes)
	rows := strings.Split(a_string, "\n") // ignore header bit of the csv
	rows = rows[0 : len(rows)-1]

	return rows
}

func users_list() []User {
	lines := file_lines("accounts.csv")

	users := make([]User, len(lines))
	for i := 0; i < len(lines); i++ {
		cols := strings.Split(lines[i], ",")

		users[i].Name = cols[0]
		users[i].IsAdmin = false
		if cols[3] == "yes" {
			users[i].IsAdmin = true
		}
	}

	return users
}

func user_is_name_unique(new_name string) bool {
	rows := file_lines("accounts.csv")

	for i := 0; i < len(rows); i++ {
		row := rows[i]
		cols := strings.Split(row, ",")
		if cols[0] == new_name {
			return false
		}
	}

	return true
}

func user_add(username string, password string, is_admin bool, code string) {
	salt := base64_random(16)
	hashed_password := salt_and_hash(salt, password, username)

	f, _ := os.OpenFile("accounts.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	admin_str := "no"
	if is_admin {
		admin_str = "yes"
	}

	f.Write([]byte(username + "," + hashed_password + "," + salt + "," + admin_str + "," + code + "\n"))

	f.Close()
}

func user_remove(username string, only_if_not_admin bool) {
	lines := file_lines("accounts.csv")

	newdata := ""
	for i := 0; i < len(lines); i++ {
		cols := strings.Split(lines[i], ",")
		row_name := cols[0]
		fmt.Println("comparing: ", row_name, "and", username)

		if cols[3] == "yes" && only_if_not_admin {
			newdata += lines[i] + "\n"
		} else if row_name != username {
			newdata += lines[i] + "\n"
		}
	}

	ioutil.WriteFile("accounts.csv", []byte(newdata), 0644)
}

func user_login(in_username string, in_password string) (user User, error error) {
	rows := file_lines("accounts.csv")

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
			fmt.Println("comparing hashed passwords: ", h, "and", hashed_password)
			if h == hashed_password {
				fmt.Println("match")
				// user is verified
				var u User
				u.Name = name
				u.IsAdmin = (is_admin == "yes")

				// generate a random unique cookie
				u.Authcode = base64_random(128)
				unique := false
				for !unique {
					unique = true
					for i := 0; i < len(active_users); i++ {
						if active_users[i].Authcode == u.Authcode {
							unique = false
							u.Authcode = base64_random(128)
						}
					}
				}

				// fmt.Println("found user, made id: ", u.Authcode)

				return u, nil
			} else {
				// not verified wrong password
				return User{}, errors.New("Wrong password")
			}
		}
	}

	// on success add active user +
	// on fail send error message
	return User{}, errors.New("Wrong username")
}

func regcode_is_valid(code string) bool {
	valid_codes := file_lines("registercodes.txt")

	for i := 0; i < len(valid_codes); i++ {
		if valid_codes[i] == code {
			return true
		}
	}

	return false
}

func regcode_add(code string) {
	f, _ := os.OpenFile("registercodes.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	f.Write([]byte(code + "\n"))

	f.Close()
}

func regcode_remove(code string) {
	c_data, _ := ioutil.ReadFile("registercodes.txt")

	newdata := strings.Replace(string(c_data), code+"\n", "", 1)

	ioutil.WriteFile("registercodes.txt", []byte(newdata), 0644)
}

type Post struct {
	title   string
	author  string
	content string
	id      string
}
type Comment struct {
	id      string
	author  string
	content string
}

var posts []Post

// quickly turn id into map
var posts_ids_map map[string]int

func posts_load(filename string) {
	posts_ids_map = make(map[string]int)
	lines := file_lines(filename)

	fmt.Println(lines)
	posts = make([]Post, len(lines))

	for i := 0; i < len(posts); i++ {
		var post Post

		cols := strings.SplitN(lines[i], ",", 4)
		fmt.Println(cols[0])
		fmt.Println(cols[1])

		post.author = cols[0]
		post.title = cols[1]
		post.id = cols[2]
		post.content = cols[3][1 : len(cols)-1]

		posts[i] = post
		posts_ids_map[post.id] = i
	}
}

func posts_write() {
	f, _ := os.OpenFile("posts.csv", os.O_CREATE|os.O_WRONLY, 0666)

	for i := 0; i < len(posts); i++ {
		post := posts[i]

		f.Write([]byte(post.author + ","))
		f.Write([]byte(post.title + ","))
		f.Write([]byte(post.id + ","))
		f.Write([]byte("\"" + post.content + "\"\n"))
	}

	f.Close()
}

func posts_add(title string, author string, content string) (post_id string) {
	id := base64_random(12)
	unique := false
	for !unique {
		unique = true
		for i := 0; i < len(posts); i++ {
			if id == posts[i].id {
				unique = false
			}
		}
	}

	var post Post
	post.author = author
	post.title = title
	post.content = content
	post.id = id
	posts = append(posts, post)

	posts_write()

	return id
}
func posts_remove(post_id string) {
	index := posts_ids_map[post_id]

	// remove from array
	posts = append(posts[:index], posts[index+1:]...)

	// remove from map
	delete(posts_ids_map, post_id)

	posts_write()
}
func posts_comment_add(id string, author string, comment string) string {
	f, _ := os.OpenFile("comments/"+id+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	comment_id := base64_random(20)

	f.Write([]byte(comment_id + "," + author + "," + comment + "\n"))

	f.Close()
	return comment_id
}
func posts_comments_list(id string, author string, comment string) []Comment {
	lines := file_lines("coments/" + id + ".txt")
	comments := make([]Comment, len(lines))

	for i := 0; i < len(lines); i++ {
		cols := strings.SplitN(lines[i], ",", 3)

		comments[i].id = cols[0]
		comments[i].author = cols[1]
		comments[i].content = cols[2]
	}

	return comments
}

func posts_comment_remove(post_id string, comment_id string, author string) {
	lines := file_lines("comments/" + post_id + ".txt")
	fmt.Println("trying to remove", comment_id)

	newdata := ""
	for i := 0; i < len(lines); i++ {
		cols := strings.SplitN(lines[i], ",", 3)
		c_id := cols[0]
		c_a := cols[1]

		if comment_id != c_id || c_a != author {
			newdata += lines[i] + "\n"
		}
	}

	ioutil.WriteFile("comments/"+post_id+".txt", []byte(newdata), 0666)
}

func main() {
	// this ensures only 1 physical cpu being used, prevents race conditions
	runtime.GOMAXPROCS(1)

	// regcode_add("lennoxisreal")
	// user_add("bob", "password", true, "")
	// user_add("seriousadmin", "yolo", true, "")
	// user_add("janitor", "incorrect", true, "")
	// user_add("alice", "realAlice", false, "")
	// user_add("john", "6969", false, "")
	// user_add("luke", "1234", false, "")
	// user_add("realluke", "theyhatedlukebecausehetoldthetruth", false, "")
	// user_add("stevethebeast", "coldplay2007", false, "")

	head, err := ioutil.ReadFile("templates/head.html")
	if err != nil {
		fmt.Println("no head file!")
	}
	tail, err := ioutil.ReadFile("templates/tail.html")
	if err != nil {
		fmt.Println("no tail file!")
	}
	fail_html, err := ioutil.ReadFile("templates/fail.html")
	if err != nil {
		fmt.Println("no fail file!")
	}

	fail_template := template.New("fail")
	fail_template, err = fail_template.Parse(string(fail_html))

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

	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		body, _ := ioutil.ReadFile("templates/admin.html")
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

		r.ParseForm()
		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")

		user, err := user_login(username, password)

		if err != nil {
			fail_template.Execute(w, "Wrong username or password, try again...")
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
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		success_page, _ := ioutil.ReadFile("templates/success.html")

		r.ParseForm()
		username := r.PostForm.Get("username")
		code := r.PostForm.Get("code")
		pass1 := r.PostForm.Get("password1")
		pass2 := r.PostForm.Get("password2")

		// is code valid
		if !regcode_is_valid(code) {
			// say code isn't valid
			fail_template.Execute(w, "Registration code not valid, try again...")
		} else if pass1 != pass2 {
			// passwords don't match
			fail_template.Execute(w, "Passwords didn't match, try again...")

		} else if !user_is_name_unique(username) {
			// is username taken
			fail_template.Execute(w, "Username already in use, try again...")
		} else {

			// add the user
			user_add(username, pass1, false, code)

			user, _ := user_login(username, pass1)

			c := http.Cookie{Name: "authcode", Value: user.Authcode, Expires: time.Now().Add(6 * time.Hour)}
			c.SameSite = http.SameSiteStrictMode
			http.SetCookie(w, &c)
			active_users = append(active_users, user)

			// show succesful login page
			w.Write(success_page)
			regcode_remove(code)
		}
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

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
	http.HandleFunc("/deluser", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if err == nil && user.IsAdmin {
			r.ParseForm()
			username := r.Form.Get("name")
			user_remove(username, true)
		}
	})
	http.HandleFunc("/ui-admintable", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// check credentials
		if err == nil && user.IsAdmin {
			// show fellow admins just for kicks
			users := users_list()

			fmt.Fprintf(w, "<p> Fellow admins :) </p>")
			fmt.Fprintf(w, "<ul>")
			for i := 0; i < len(users); i++ {
				if users[i].IsAdmin {
					fmt.Fprintf(w, "<li> "+users[i].Name+" </li>")
				}
			}
			fmt.Fprintf(w, "</ul>")

			fmt.Fprintf(w, "<p> Regular users: </p>")
			fmt.Fprintf(w, "<ul>")
			// list every non admin user, for deletion

			for i := 0; i < len(users); i++ {
				if !users[i].IsAdmin {
					fmt.Fprintf(w, "<li id=\"userline\"> "+users[i].Name+"<div class=\"x\" hx-trigger=\"click\" hx-target=\"closest #userline\" hx-swap=\"outerHTML\" hx-post=\"/deluser?name="+users[i].Name+"\" hx-confirm=\"Are you sure you want to delete this user and all their posts?\"><b>X</b></div> </li>")
				}
			}
			fmt.Fprintf(w, "</ul>")
		}
	})
	http.HandleFunc("/ui-loginbutton", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		if err != nil {
			fmt.Fprintf(w, "<a href=\"/login\" class=\"nav-item\">LOGIN/REGISTER</a>")
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
