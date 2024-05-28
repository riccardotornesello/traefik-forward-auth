package providers

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"traefikauth.riccardotornesello.it/config"
)

func CreateJWT(email string, groupsDirect []interface{}) (string, error) {
	config := config.GetConfig()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":    time.Now().Unix(),
		"email":  email,
		"groups": groupsDirect,
	})

	tokenString, err := token.SignedString([]byte(config.Secret))

	return tokenString, err
}

func ParseJWT(tokenString string) (string, []string, error) {
	config := config.GetConfig()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.Secret), nil
	})

	if err != nil {
		return "", nil, err
	}

	if !token.Valid {
		return "", nil, fmt.Errorf("Invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", nil, fmt.Errorf("Invalid claims")
	}

	// Check max age
	if time.Now().Unix()-int64(claims["iat"].(float64)) > config.AuthDuration {
		return "", nil, fmt.Errorf("Token expired")
	}

	email, ok := claims["email"].(string)
	if !ok {
		return "", nil, fmt.Errorf("Invalid email")
	}

	groups, ok := claims["groups"].([]interface{})
	if !ok {
		return "", nil, fmt.Errorf("Invalid groups")
	}

	var groupsString []string
	for _, group := range groups {
		groupString, ok := group.(string)
		if !ok {
			return "", nil, fmt.Errorf("Invalid group")
		}
		groupsString = append(groupsString, groupString)
	}

	return email, groupsString, nil
}
