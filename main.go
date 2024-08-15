package main

import (
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("chave_secreta_do_jwt")

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/api", authMiddleware(apiHandler))

	fmt.Println("Servidor iniciado na porta 8080")
	http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	// Verifica as credenciais do usuário
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Verifica se as credenciais são válidas
	if username == "usuario" && password == "senha" {
		// Cria um token JWT com uma data de expiração
		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Retorna o token JWT para o cliente
		w.Write([]byte(tokenString))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Obtém o token JWT do cabeçalho da requisição
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Valida o token JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Chama o próximo handler
		next(w, r)
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("API Rest protegida por autenticação e autorização com JWT"))
}
