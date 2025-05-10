package main

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	db          *sql.DB
	jwtSecret   = []byte("your-secret-key") // Замените на свой секретный ключ
	tokenExpiry = time.Hour * 24            // Токен действует 24 часа
)

type Todo struct {
	ID        int    `json:"id"`
	Title     string `json:"title" binding:"required"`
	Completed bool   `json:"completed"`
	UserID    int    `json:"user_id"` // Связь с пользователем
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// Инициализация базы данных
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./todos.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS todos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			completed BOOLEAN NOT NULL DEFAULT 0,
			user_id INTEGER,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

// Middleware для проверки JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

// Регистрация пользователя
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	res, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	id, _ := res.LastInsertId()
	user.ID = int(id)
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "username": user.Username})
}

// Логин и выдача JWT
func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var storedUser User
	var hashedPassword string
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", user.Username).
		Scan(&storedUser.ID, &storedUser.Username, &hashedPassword)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(tokenExpiry)
	claims := &Claims{
		UserID:   storedUser.ID,
		Username: storedUser.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// CRUD операции для Todo
func getTodos(c *gin.Context) {
	userID, _ := c.Get("user_id")
	rows, err := db.Query("SELECT id, title, completed, user_id FROM todos WHERE user_id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	todos := []Todo{}
	for rows.Next() {
		var t Todo
		if err := rows.Scan(&t.ID, &t.Title, &t.Completed, &t.UserID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		todos = append(todos, t)
	}

	c.JSON(http.StatusOK, todos)
}

func getTodo(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id := c.Param("id")
	var t Todo
	err := db.QueryRow("SELECT id, title, completed, user_id FROM todos WHERE id = ? AND user_id = ?", id, userID).
		Scan(&t.ID, &t.Title, &t.Completed, &t.UserID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, t)
}

func createTodo(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var t Todo
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := db.Exec("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)", t.Title, t.Completed, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	id, _ := res.LastInsertId()
	t.ID = int(id)
	t.UserID = userID.(int)
	c.JSON(http.StatusCreated, t)
}

func updateTodo(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id := c.Param("id")
	var t Todo
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec("UPDATE todos SET title = ?, completed = ? WHERE id = ? AND user_id = ?", t.Title, t.Completed, id, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	t.ID, _ = strconv.Atoi(id)
	t.UserID = userID.(int)
	c.JSON(http.StatusOK, t)
}

func deleteTodo(c *gin.Context) {
	userID, _ := c.Get("user_id")
	id := c.Param("id")
	result, err := db.Exec("DELETE FROM todos WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Todo not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	// Публичные маршруты
	r.POST("/register", register)
	r.POST("/login", login)

	// Защищенные маршруты
	protected := r.Group("/todos").Use(authMiddleware())
	{
		protected.GET("", getTodos)
		protected.GET("/:id", getTodo)
		protected.POST("", createTodo)
		protected.PUT("/:id", updateTodo)
		protected.DELETE("/:id", deleteTodo)
	}

	log.Fatal(r.Run(":8080"))
}