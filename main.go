package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// CONNECT DATABASE
func connectDB() {
	connStr := "user=postgres password=1234 dbname=authdb sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
}

// SHOW SIGNUP PAGE
func showSignup(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/signup.html"))
	tmpl.Execute(w, nil)
}

// SHOW LOGIN PAGE
func showLogin(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	tmpl.Execute(w, nil)
}

// HASH PASSWORD
func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes)
}

// SIGNUP LOGIC
func signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	hashed := hashPassword(password)

	_, err := db.Exec(
		"INSERT INTO users(username, password) VALUES($1,$2)",
		username, hashed,
	)

	if err != nil {
		fmt.Fprintln(w, "Username already exists")
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// LOGIN LOGIC
func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var hashed string
	err := db.QueryRow(
		"SELECT password FROM users WHERE username=$1",
		username,
	).Scan(&hashed)

	if err != nil {
		fmt.Fprintln(w, "User not found")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err != nil {
		fmt.Fprintln(w, "Wrong password")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: username,
		Path:  "/",
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// DASHBOARD
func dashboard(w http.ResponseWriter, r *http.Request) {
	_, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/dashboard.html"))
	tmpl.Execute(w, nil)
}

// LOGOUT
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func main() {
	connectDB()

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.HandleFunc("/signup", showSignup)
	http.HandleFunc("/login", showLogin)

	http.HandleFunc("/signup-submit", signup)
	http.HandleFunc("/login-submit", login)

	http.HandleFunc("/dashboard", dashboard)
	http.HandleFunc("/logout", logout)

	fmt.Println("Server running at http://localhost:8080")

	http.ListenAndServe(":8080", nil)
}
