package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/acme"
)

var challenges = make(map[string]string)

type GenerateRequest struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

type GenerateResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "SSL Generator Backend Running 🚀")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	go requestCertificate(req.Domain, req.Email)

	response := GenerateResponse{
		Status:  "processing",
		Message: "Certificate request started for " + req.Domain,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Path[len("/.well-known/acme-challenge/"):]
	value, exists := challenges[token]

	if !exists {
		http.NotFound(w, r)
		return
	}

	fmt.Fprint(w, value)
}

func setChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	json.NewDecoder(r.Body).Decode(&data)

	token := data["token"]
	value := data["value"]

	challenges[token] = value

	w.Write([]byte("Challenge stored"))
}

func requestCertificate(domain string, email string) {
	ctx := context.Background()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	client := &acme.Client{
		Key:          privateKey,
		DirectoryURL: acme.LetsEncryptStagingURL,
	}

	account := &acme.Account{
		Contact: []string{"mailto:" + email},
	}

	client.Register(ctx, account, acme.AcceptTOS)

	order, _ := client.AuthorizeOrder(ctx, []string{domain})

	for _, authURL := range order.AuthzURLs {
		auth, _ := client.GetAuthorization(ctx, authURL)

		for _, chal := range auth.Challenges {
			if chal.Type == "http-01" {
				resp, _ := client.HTTP01ChallengeResponse(chal.Token)
				challenges[chal.Token] = resp
				client.Accept(ctx, chal)
			}
		}
	}

	client.WaitAuthorization(ctx, order.AuthzURLs[0])

	fmt.Println("Challenge accepted for", domain)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/.well-known/acme-challenge/", challengeHandler)
	http.HandleFunc("/set-challenge", setChallengeHandler)

	fmt.Println("Server running on port", port)
	http.ListenAndServe(":"+port, nil)
}
