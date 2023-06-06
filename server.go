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

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

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

var POSSIBLE_ID_CHARACTERS = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func random_id(length int) string {
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
	salt := random_id(16)
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
				u.Authcode = random_id(128)
				unique := false
				for !unique {
					unique = true
					for i := 0; i < len(active_users); i++ {
						if active_users[i].Authcode == u.Authcode {
							unique = false
							u.Authcode = random_id(128)
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

func regcodes_list() []string {
	return file_lines("registercodes.txt")
}

func regcode_remove(code string) {
	lines := file_lines("registercodes.txt")

	newdata := ""

	for i := 0; i < len(lines); i++ {
		fmt.Println("comparing: ", lines[i], "and", code)
		if lines[i] != code {
			newdata += lines[i] + "\n"
		}
	}

	ioutil.WriteFile("registercodes.txt", []byte(newdata), 0666)
}

type Post struct {
	Title        string
	DisplayTitle string
	Author       string
	Content      string
	Id           string
}
type Comment struct {
	Id      string
	Author  string
	Content string
}

var posts []Post

// quickly turn id into map
var posts_ids_map map[string]int

func posts_load(filename string) {
	lines := file_lines(filename)

	if posts_ids_map == nil {
		posts_ids_map = make(map[string]int)
	}

	fmt.Println(lines)
	posts = make([]Post, len(lines))

	for i := 0; i < len(posts); i++ {
		var post Post

		cols := strings.SplitN(lines[i], ",", 4)
		if len(cols) > 3 {
			fmt.Println(cols[0])
			fmt.Println(cols[1])

			post.Author = cols[0]
			post.Title = cols[1]
			post.DisplayTitle = strings.ReplaceAll(cols[1], "\r||\r", ",")
			post.Id = cols[2]
			post.Content = strings.ReplaceAll(cols[3][1:len(cols[3])-1], "<br>", "\r\n")

			posts[i] = post
			posts_ids_map[post.Id] = i
		}
	}
}

func posts_search(query string) []Post {
	matches := make([]Post, len(posts))
	match_count := 0
	query = strings.ToLower(query)

	for i := 0; i < len(posts); i++ {
		search_domain := strings.ToLower(posts[i].Title + " " + posts[i].Author + " " + posts[i].Content)

		if strings.Index(search_domain, query) != -1 {
			matches[match_count] = posts[i]
			match_count++
		}
	}

	return matches[:match_count]
}

func posts_write() {
	os.Remove("posts.csv")
	f, _ := os.OpenFile("posts.csv", os.O_CREATE|os.O_WRONLY, 0666)

	for i := 0; i < len(posts); i++ {
		post := posts[i]

		f.Write([]byte(post.Author + ","))
		f.Write([]byte(post.Title + ","))
		f.Write([]byte(post.Id + ","))
		stored := strings.ReplaceAll(post.Content, "\r\n", "<br>")
		f.Write([]byte("\"" + stored + "\"\n"))
	}

	f.Close()
}

func posts_add(title string, author string, content string) (post_id string) {
	id := random_id(12)
	unique := false
	for !unique {
		unique = true
		for i := 0; i < len(posts); i++ {
			if id == posts[i].Id {
				unique = false
			}
		}
	}

	var post Post
	post.Author = author
	post.DisplayTitle = title
	post.Title = strings.ReplaceAll(title, ",", "\r||\r")
	post.Content = content
	post.Id = id
	posts = append(posts, post)

	if posts_ids_map == nil {
		posts_ids_map = make(map[string]int)
	}

	posts_ids_map[post.Id] = len(posts) - 1

	posts_write()

	return id
}
func posts_remove(post_id string) {
	index := posts_ids_map[post_id]

	// remove from array
	posts = append(posts[:index], posts[index+1:]...)

	// remove from map
	delete(posts_ids_map, post_id)
	posts_ids_map = make(map[string]int)

	// recalculate entire map
	for i := 0; i < len(posts); i++ {
		posts_ids_map[posts[i].Id] = i
	}

	posts_write()
}
func posts_comment_add(id string, author string, comment string) string {
	f, _ := os.OpenFile("comments/"+id+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	comment_id := random_id(20)

	f.Write([]byte(comment_id + "," + author + "," + comment + "\n"))

	f.Close()
	return comment_id
}
func posts_comments_list(id string) []Comment {
	lines := file_lines("./comments/" + id + ".txt")
	comments := make([]Comment, len(lines))

	for i := 0; i < len(lines); i++ {
		cols := strings.SplitN(lines[i], ",", 3)

		comments[i].Id = cols[0]
		comments[i].Author = cols[1]
		comments[i].Content = cols[2]
	}

	return comments
}

func posts_comment_remove(post_id string, comment_id string, author string, remove_on_author_match bool) {
	lines := file_lines("comments/" + post_id + ".txt")
	fmt.Println("trying to remove", comment_id)

	newdata := ""
	for i := 0; i < len(lines); i++ {
		cols := strings.SplitN(lines[i], ",", 3)
		c_id := cols[0]
		c_a := cols[1]

		if (remove_on_author_match && c_a == author) || (comment_id == c_id) {
			fmt.Println("removed comment")
			// don't store
		} else {
			newdata += lines[i] + "\n"
		}
	}

	ioutil.WriteFile("comments/"+post_id+".txt", []byte(newdata), 0666)
}

func main() {
	// this ensures only 1 physical cpu being used, prevents race conditions
	runtime.GOMAXPROCS(1)

	// user_add("admin", "admin", true, "")
	// user_add("bob", "password", true, "")
	// user_add("seriousadmin", "yolo", true, "")
	// user_add("janitor", "incorrect", true, "")
	// user_add("alice", "realAlice", false, "")
	// user_add("john", "6969", false, "")
	// user_add("luke", "1234", false, "")
	// user_add("realluke", "theyhatedlukebecausehetoldthetruth", false, "")
	// user_add("stevethebeast", "coldplay2007", false, "")
	user_add("spammer", "thelegend27", false, "")

	// posts_add("First post", "admin", "behold the first ever post on this forum website. I hope you all enjoy this thing.")
	// i1 := posts_add("Another post from admin", "admin", "How's everyone feeling today? I'm doing excellent!!")
	// posts_comment_add(i1, "john", "yeah im doing fine")
	// posts_comment_add(i1, "luke", "i don't know how you do it john. I'm so stressed over exams")
	// posts_comment_add(i1, "john", "it's about being yourself and staying in the moment maaan")
	// posts_comment_add(i1, "janitor", "ok bozos, that's enough. Don't make me ban yalll")

	posts_add("Spammer spam!!", "spammer", "I LOVE SPAM HAHAHHAHAHAHHAH")
	posts_add("Spamming", "spammer", "I LOVE SPAM HAHAHHAHAHAHHAH")
	posts_add("Spamm time", "spammer", "I LOVE SPAM HAHAHHAHAHAHHAH")
	posts_add("spamsisters lets go", "spammer", "I LOVE SPAM HAHAHHAHAHAHHAH")
	posts_add("Spammer spam spam there is no escape!", "spammer", "I LOVE SPAM HAHAHHAHAHAHHAH")

	// i1 = posts_add("Hey any updates on the INFO2222 exam", "luke", "I haven't seen anything on canvas maybe some tutor spilled the beans?")
	// posts_comment_add(i1, "john", "yeah that would be neat if someone had that")
	// posts_comment_add(i1, "spammer", "get spammed on loser")
	// posts_comment_add(i1, "spammer", "HAHAHHAHA")
	// posts_comment_add(i1, "spammer", "HAHAHHAHA")
	// posts_comment_add(i1, "spammer", "get spammed on loser")
	// posts_comment_add(i1, "spammer", "HAHAHHAHA")
	// posts_comment_add(i1, "spammer", "HAHAHHAHA")
	// posts_comment_add(i1, "spammer", "get spammed on loser")
	// posts_comment_add(i1, "spammer", "HAHAHHAHA")
	// posts_comment_add(i1, "spammer", "get spammed on loser")
	// posts_comment_add(i1, "janitor", "ok spammer bozo, that's enough. Don't make me ban yalll")
	// posts_comment_add(i1, "spammer", "I'm invincible!!!!")
	// posts_comment_add(i1, "alice", "im study vet, over here teachers usually spill the beans")

	posts_load("posts.csv")

	fmt.Println(posts)

	head_html, err := ioutil.ReadFile("templates/head.html")
	if err != nil {
		fmt.Println("no head file!")
	}
	index_html, err := ioutil.ReadFile("templates/index.html")
	if err != nil {
		fmt.Println("no index file!")
	}
	tail, err := ioutil.ReadFile("templates/tail.html")
	if err != nil {
		fmt.Println("no tail file!")
	}
	fail_html, err := ioutil.ReadFile("templates/fail.html")
	if err != nil {
		fmt.Println("no fail file!")
	}
	post_html, err := ioutil.ReadFile("templates/post.html")
	if err != nil {
		fmt.Println("no post file!")
	}

	fail_template := template.New("fail")
	fail_template, err = fail_template.Parse(string(fail_html))

	head_template := template.New("head")
	head_template, err = head_template.Parse(string(head_html))

	index_template := template.New("index")
	index_template, err = index_template.Parse(string(index_html))

	post_template := template.New("post")
	post_template, err = post_template.Parse(string(post_html))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		head_template.Execute(w, user)
		posts_rev := make([]Post, len(posts))
		for i := 0; i < len(posts); i++ {
			posts_rev[(len(posts)-1)-i] = posts[i]
		}

		index_template.Execute(w, posts_rev)
		w.Write(tail)
	})

	http.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		body, _ := ioutil.ReadFile("templates/about.html")
		head_template.Execute(w, user)
		w.Write(body)
		w.Write(tail)
	})

	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		body, _ := ioutil.ReadFile("templates/admin.html")
		head_template.Execute(w, user)
		w.Write(body)
		w.Write(tail)
	})

	http.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		body, _ := ioutil.ReadFile("templates/login.html")
		head_template.Execute(w, user)
		w.Write(body)
		w.Write(tail)
	})
	http.HandleFunc("/newpost", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if err == nil {
			body, _ := ioutil.ReadFile("templates/newpost.html")
			head_template.Execute(w, user)
			w.Write(body)
			w.Write(tail)
		} else {
			fail_template.Execute(w, "you're not allowed to make posts, try logging in or registering")
		}
	})
	http.HandleFunc("/newcode", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if user.IsAdmin && err == nil {
			code := random_id(16)
			regcode_add(code)

			http.Redirect(w, r, r.URL.Host+"/ui-admininvites", http.StatusSeeOther)
		}
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

			http.Redirect(w, r, r.URL.Host, http.StatusSeeOther)
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

			for i := 0; i < len(posts); i++ {
				// delete all comments by user
				posts_comment_remove(posts[i].Id, "", username, true)

				fmt.Println("comparing: ", posts[i].Author, "and", username)
				if posts[i].Author == username {
					// delete all posts by user
					fmt.Println("Removing post: ", posts[i].Author)
					posts_remove(posts[i].Id)
				}
			}

			user_remove(username, true)
		}
	})
	http.HandleFunc("/posts/", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		// make sure it's an admin
		id := r.URL.Path[len("/posts/"):]
		index, ok := posts_ids_map[id]
		fmt.Println("id: ", id)

		if !ok {
			// return error
			fail_template.Execute(w, "No post with that id was found, sorry bro")
		} else {
			fmt.Println("post found sending thing right away")
			head_template.Execute(w, user)

			text := posts[index].Content

			text = template.HTMLEscapeString(text)
			text = strings.ReplaceAll(text, "\r\n", "<br>")
			text_html := template.HTML(text)

			og_title := posts[index].Title
			posts[index].Title = strings.ReplaceAll(posts[index].Title, "\r||\r", ",")

			post_template.Execute(w, struct {
				PData   Post
				Content template.HTML
			}{posts[index], text_html})
			posts[index].Title = og_title

			w.Write(tail)
		}
	})
	http.HandleFunc("/ui-search", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		r.ParseForm()
		query := r.Form.Get("query")
		matching_posts := posts_search(query)
		matching_posts_rev := make([]Post, len(matching_posts))

		for i := 0; i < len(matching_posts); i++ {
			matching_posts_rev[(len(matching_posts)-1)-i] = matching_posts[i]
		}

		index_template.Execute(w, matching_posts_rev)
	})
	http.HandleFunc("/makepost", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if err == nil {
			r.ParseForm()
			title := r.PostForm.Get("title")
			content := r.PostForm.Get("content")

			id := posts_add(title, user.Name, content)

			http.Redirect(w, r, r.URL.Host+"/posts/"+id, http.StatusSeeOther)
		}
	})
	http.HandleFunc("/makecomment", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if err == nil {
			r.ParseForm()
			content := r.PostForm.Get("comment")
			id := r.PostForm.Get("id")

			posts_comment_add(id, user.Name, content)

			http.Redirect(w, r, r.URL.Host+"/posts/"+id, http.StatusSeeOther)
		}
	})
	http.HandleFunc("/ui-comments", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		r.ParseForm()
		id := r.Form.Get("id")

		authcode := authcode_from_request(r)
		user, _ := user_from_authcode(authcode)

		comments := posts_comments_list(id)
		for i := 0; i < len(comments); i++ {
			if user.IsAdmin || comments[i].Author == user.Name {
				// fmt.Fprint(w, "<div=\"comment\"><i>", comments[i].Author, "<i>:", comments[i].Content)
				// fmt.Fprint(w, "<div class=\"x\" hx-trigger=\"click\" hx-target=\"closest #userline\" hx-swap=\"outerHTML\" hx-get=\"/delcomment?id=", id, "&cid="+comments[i].Id+"\" hx-confirm=\"Delete comment?\"><b>X</b></div> </div>")
				fmt.Fprint(w, "<div class=\"comment\"><i><b>", comments[i].Author, "</b></i>: ", comments[i].Content)
				fmt.Fprint(w, "<div class=\"x\" hx-trigger=\"click\" hx-target=\"closest .comment\" hx-swap=\"outerHTML\" hx-get=\"/delcomment?id=", id, "&cid="+comments[i].Id+"\" hx-confirm=\"Delete comment?\"><b>X</b></div>")
				fmt.Fprint(w, "</div>")
			} else {
				fmt.Fprint(w, "<div class=\"comment\"><i><b>", comments[i].Author, "</b></i>: ", comments[i].Content, "</div>")
			}
		}
	})
	http.HandleFunc("/delpost", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if err == nil {
			r.ParseForm()
			id := r.PostForm.Get("id")
			index, ok := posts_ids_map[id]

			if ok {
				if user.IsAdmin || posts[index].Author == user.Name {
					posts_remove(id)
					http.Redirect(w, r, r.URL.Host, http.StatusSeeOther)
				}
			}
		}
	})
	http.HandleFunc("/delcomment", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's user
		if err == nil {
			r.ParseForm()
			id := r.Form.Get("id")
			cid := r.Form.Get("cid")
			index, ok := posts_ids_map[id]
			fmt.Println("planning to remove removing comment: ", id, cid, user.Name)

			if ok {
				if user.IsAdmin || posts[index].Author == user.Name {
					fmt.Println("removing comment: ", id, cid, user.Name)
					posts_comment_remove(id, cid, "", false)
				}
			}
		}
	})
	http.HandleFunc("/delcode", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// make sure it's an admin
		if user.IsAdmin && err == nil {
			r.ParseForm()
			code := r.Form.Get("code")

			regcode_remove(code)
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

			fmt.Fprintf(w, "<hr>")

			fmt.Fprintf(w, "<p> Regular users: </p>")
			fmt.Fprintf(w, "<ul>")
			// list every non admin user, for deletion

			for i := 0; i < len(users); i++ {
				if !users[i].IsAdmin {
					fmt.Fprintf(w, "<li id=\"userline\"> "+users[i].Name+"<div class=\"x\" hx-trigger=\"click\" hx-target=\"closest #userline\" hx-swap=\"outerHTML\" hx-get=\"/deluser?name="+users[i].Name+"\" hx-confirm=\"Are you sure you want to delete this user and all their posts?\"><b>X</b></div> </li>")
				}
			}
			fmt.Fprintf(w, "</ul>")
		}
	})

	http.HandleFunc("/ui-admininvites", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		// check credentials
		if err == nil && user.IsAdmin {
			fmt.Fprintf(w, "<p> Invite codes: </p>")
			fmt.Fprintf(w, "<ul>")
			// list every non admin user, for deletion

			codes := regcodes_list()
			for i := 0; i < len(codes); i++ {
				fmt.Fprint(w, "<li id=\"userline\">", codes[i], "<div class=\"x\" hx-trigger=\"click\" hx-target=\"closest #userline\" hx-swap=\"outerHTML\" hx-get=\"/delcode?code=", codes[i], "\" hx-confirm=\"Delete invite code", codes[i], "?\"><b>X</b></div> </li>")
			}
			fmt.Fprintf(w, "</ul>")
		}
	})
	http.HandleFunc("/ui-postbutton", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		_, err := user_from_authcode(authcode)

		if err != nil {
		} else {
			fmt.Fprintf(w, "<a href=\"/newpost\" id=\"makepostbutton\" class=\"button\"> New Post </a>")
		}
	})
	http.HandleFunc("/ui-controls", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		user, err := user_from_authcode(authcode)

		if err != nil {
		} else {
			r.ParseForm()
			id := r.Form.Get("id")
			index, ok := posts_ids_map[id]

			if ok {
				if user.IsAdmin || posts[index].Author == user.Name {
					fmt.Fprint(w, `<form method="post" action="/delpost"><input class="hidden" name="id" type="text" value="`+id+`"></input><input type="submit" value="Delete post"></input></form>`)
				}
			} else {
				fmt.Println("NOT OK DANGER GDANGER")
			}
		}
	})
	http.HandleFunc("/ui-commentbox", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)

		authcode := authcode_from_request(r)
		_, err := user_from_authcode(authcode)

		if err != nil {
		} else {
			r.ParseForm()
			id := r.Form.Get("id")
			_, ok := posts_ids_map[id]

			if ok {
				fmt.Fprintf(w, "<form action=\"/makecomment\" method=\"post\"><input class=\"hidden\" name=\"id\" value=\""+id+"\"></input><input name=\"comment\" id=\"commentbox\" type=\"text\" placeholder=\"Leave a comment\"> </input> <input type=\"submit\" value=\"Post comment\"></input> </form>")
			}

		}
	})

	port := "9696"
	fmt.Println("Starting server...\n\tPort:\t\t", port, "\n\tUnix time:\t", time.Now().Unix())

	err = http.ListenAndServeTLS(":"+string(port), "certs/cert.pem", "certs/key.pem", nil)
	fmt.Println(err)
}
