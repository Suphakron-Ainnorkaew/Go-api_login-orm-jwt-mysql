package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"

	_ "golang.org/x/crypto/bcrypt"
)

func JWTAuthen() gin.HandlerFunc {
	return func(c *gin.Context) {
		hmacSampleSecret := []byte(os.Getenv("JWT_SECRET_KEY"))
		header := c.Request.Header.Get("Authorization")

		tokenString := strings.Replace(header, "Bearer ", "", 1)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			return hmacSampleSecret, nil
		})
		if Claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("userId", Claims["userId"])
		} else {
			c.AbortWithStatusJSON(http.StatusOK, gin.H{"status": "ss", "message": err.Error()})
		}

		c.Next()
	}
}

//
//c.Next()

//latency := time.Since(t)
//log.Print(latency)
