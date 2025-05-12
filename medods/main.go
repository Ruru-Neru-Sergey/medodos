package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"github.com/swaggo/files"
    "github.com/swaggo/gin-swagger"
)

func main() {
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := gin.Default()

	// Endpoints
	r.GET("/auth/tokens", func(c *gin.Context) {
		guid := c.Query("guid")
		if guid == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "guid is required"})
			return
		}

		accessToken, _ := createToken(guid, os.Getenv("JWT_SECRET"))
		refreshToken := "random-refresh-token"
		hash, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
		
		db.Exec("INSERT INTO refresh_tokens (user_guid, token_hash, user_agent, ip) VALUES ($1, $2, $3, $4)",
			guid, string(hash), c.GetHeader("User-Agent"), c.ClientIP())

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	})

	r.POST("/auth/refresh", func(c *gin.Context) {
		var req struct{ RefreshToken string }
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
			return
		}

		accessToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		claims, err := parseToken(accessToken, os.Getenv("JWT_SECRET"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		guid := claims["sub"].(string)
		var tokenHash string
		err = db.QueryRow("SELECT token_hash FROM refresh_tokens WHERE user_guid = $1 AND is_used = false ORDER BY created_at DESC LIMIT 1", guid).Scan(&tokenHash)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(req.RefreshToken)) != nil {
			db.Exec("UPDATE refresh_tokens SET is_used = true WHERE user_guid = $1", guid)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}

		newAccess, _ := createToken(guid, os.Getenv("JWT_SECRET"))
		newRefresh := "new-refresh-token"
		newHash, _ := bcrypt.GenerateFromPassword([]byte(newRefresh), bcrypt.DefaultCost)
		
		db.Exec("UPDATE refresh_tokens SET is_used = true WHERE user_guid = $1", guid)
		db.Exec("INSERT INTO refresh_tokens (user_guid, token_hash, user_agent, ip) VALUES ($1, $2, $3, $4)",
			guid, string(newHash), c.GetHeader("User-Agent"), c.ClientIP())

		c.JSON(http.StatusOK, gin.H{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
		})
	})

	r.GET("/auth/me", authMiddleware(os.Getenv("JWT_SECRET")), func(c *gin.Context) {
		guid := c.GetString("guid")
		c.JSON(http.StatusOK, gin.H{"guid": guid})
	})

	r.POST("/auth/logout", authMiddleware(os.Getenv("JWT_SECRET")), func(c *gin.Context) {
		guid := c.GetString("guid")
		db.Exec("UPDATE refresh_tokens SET is_used = true WHERE user_guid = $1", guid)
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
	})

	log.Fatal(r.Run(":8080"))
}

func authMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		claims, err := parseToken(token, jwtSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("guid", claims["sub"])
		c.Next()
	}
}

func createToken(guid, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": guid,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func parseToken(tokenString, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}