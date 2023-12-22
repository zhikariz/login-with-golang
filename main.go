package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	// initialisasi file config
	cfg, err := initConfig(".env")
	if err != nil {
		panic(err)
	}

	// initialisasi database
	db, err := initDB(cfg)
	if err != nil {
		panic(err)
	}

	// inisialisasi handler
	userHandler := NewUserHandler(db)
	loginHandler := NewLoginHandler(db)

	e := echo.New()
	// routing
	e.POST("/login", loginHandler.Login)
	e.GET("/generate-password/:password", loginHandler.GeneratePassword)

	// routing auth
	admin := e.Group("/admin")

	// Configure middleware with the custom claims type
	config := echojwt.Config{
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(jwtCustomClaims)
		},
		SigningKey: []byte("secret"),
	}
	admin.Use(echojwt.WithConfig(config))
	admin.GET("/users", userHandler.GetAllUsers)
	admin.GET("/users/:id", userHandler.GetUserByID)
	admin.POST("/users", userHandler.CreateUser)
	admin.PUT("/users/:id", userHandler.UpdateUser)
	admin.DELETE("/users/:id", userHandler.DeleteUser)
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%s", cfg.Port)))
}

type Config struct {
	Port        string      `env:"PORT"`
	MysqlConfig MysqlConfig `envPrefix:"MYSQL_"`
}

type MysqlConfig struct {
	Host     string `env:"HOST"`
	Port     string `env:"PORT"`
	Username string `env:"USERNAME"`
	Password string `env:"PASSWORD"`
	Database string `env:"DATABASE"`
}

func initConfig(envPath string) (*Config, error) {
	cfg, err := parseConfig(envPath)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseConfig(envPath string) (*Config, error) {
	err := godotenv.Load(envPath)
	if err != nil {
		return nil, errors.New("failed to load env")
	}

	cfg := &Config{}
	err = env.Parse(cfg)
	if err != nil {
		return nil, errors.New("failed to parse config")
	}
	return cfg, nil
}

// table / entity user
type User struct {
	ID       int64  `json:"id"`
	Nim      string `json:"nim"`
	Nama     string `json:"nama"`
	Password string `json:"-"`
	Alamat   string `json:"alamat"`
}

func (User) TableName() string {
	return "users"
}

type UserHandler struct {
	db *gorm.DB
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{db: db}
}

type LoginHandler struct {
	db *gorm.DB
}

func NewLoginHandler(db *gorm.DB) *LoginHandler {
	return &LoginHandler{db: db}
}

type UserRequest struct {
	ID       string `param:"id"`
	Nim      string `json:"nim"`
	Nama     string `json:"nama"`
	Password string `json:"password"`
	Alamat   string `json:"alamat"`
}

type LoginRequest struct {
	Nim      string `json:"nim"`
	Password string `json:"password"`
}

// jwtCustomClaims are custom claims extending default ones.
// See https://github.com/golang-jwt/jwt for more examples
type jwtCustomClaims struct {
	ID     int64  `json:"id"`
	Nim    string `json:"nim"`
	Nama   string `json:"nama"`
	Alamat string `json:"alamat"`
	jwt.RegisteredClaims
}

func (h *LoginHandler) Login(ctx echo.Context) error {
	var input LoginRequest

	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	user := new(User)

	if err := h.db.Where("nim = ?", input.Nim).First(&user).Error; err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Incorrect Credentials"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Incorrect Credentials"})
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		user.ID,
		user.Nim,
		user.Nama,
		user.Alamat,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	generatedToken, err := token.SignedString([]byte("secret"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Generate Token"})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"message": "Succesfully Login", "token": generatedToken})
}

func (h *LoginHandler) GeneratePassword(ctx echo.Context) error {
	var input struct {
		Password string `param:"password" json:"password"`
	}
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	password, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Generate Password"})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"message": "Succesfully Generate Password", "password": string(password)})
}

func (h *UserHandler) GetAllUsers(ctx echo.Context) error {
	search := ctx.QueryParam("search")
	users := make([]*User, 0)
	query := h.db.Model(&User{})
	if search != "" {
		query = query.Where("nama LIKE ?", "%"+search+"%")
	}
	if err := query.Find(&users).Error; err != nil { // SELECT * FROM users
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Get All Users"})
	}
	return ctx.JSON(http.StatusOK, map[string]interface{}{"message": "Succesfully Get All Users", "data": users, "filter": search})
}

func (h *UserHandler) CreateUser(ctx echo.Context) error {
	var input UserRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	password := input.Password

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Generate Password"})
	}

	user := &User{
		Nim:      input.Nim,
		Nama:     input.Nama,
		Alamat:   input.Alamat,
		Password: string(hashedPassword),
	}

	if err := h.db.Create(user).Error; err != nil { // INSERT INTO users (nim, nama, alamat) VALUES('')
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Create User"})
	}

	return ctx.JSON(http.StatusCreated, map[string]interface{}{"message": "Succesfully Create a User", "data": user})
}

func (h *UserHandler) GetUserByID(ctx echo.Context) error {
	var input UserRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	user := new(User)

	if err := h.db.Where("id =?", input.ID).First(&user).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Get User By ID"})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"message": fmt.Sprintf("Succesfully Get User By ID : %s", input.ID), "data": user})
}

func (h *UserHandler) UpdateUser(ctx echo.Context) error {
	var input UserRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	userID, _ := strconv.Atoi(input.ID)

	password := input.Password

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Generate Password"})
	}

	user := User{
		ID:       int64(userID),
		Nim:      input.Nim,
		Nama:     input.Nama,
		Alamat:   input.Alamat,
		Password: string(hashedPassword),
	}

	query := h.db.Model(&User{}).Where("id = ?", userID)
	if err := query.Updates(&user).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Update User By ID", "error": err.Error()})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{"message": fmt.Sprintf("Succesfully Update User By ID : %s", input.ID), "data": input})
}

func (h *UserHandler) DeleteUser(ctx echo.Context) error {
	var input UserRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"message": "Failed to Bind Input"})
	}

	if err := h.db.Delete(&User{}, input.ID).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to Delete User By ID"})
	}
	return ctx.JSON(http.StatusNoContent, nil)
}

func initDB(cfg *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.MysqlConfig.Username,
		cfg.MysqlConfig.Password,
		cfg.MysqlConfig.Host,
		cfg.MysqlConfig.Port,
		cfg.MysqlConfig.Database,
	)
	fmt.Println(dsn)

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false,       // Don't include params in the SQL log
			Colorful:                  true,        // Disable color
		},
	)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}
