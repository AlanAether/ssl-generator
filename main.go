package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"crypto/x509"

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
	fmt.Println("Method:", r.Method)
	fmt.Println("Content-Type:", r.Header.Get("Content-Type"))

	var req GenerateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Println("Decode error:", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	fmt.Println("Received domain:", req.Domain)
	fmt.Println("Received email:", req.Email)

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
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
	}

	account := &acme.Account{
		Contact: []string{"mailto:" + email},
	}

	client.Register(ctx, account, acme.AcceptTOS)

	order, _ := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: domain},
	})

	for _, chal := range auth.Challenges {
    if chal.Type == "dns-01" {
        dnsValue, _ := client.DNS01ChallengeRecord(chal.Token)

        fmt.Println("ADD THIS DNS RECORD:")
        fmt.Println("_acme-challenge." + domain)
        fmt.Println("TXT VALUE:", dnsValue)

        // Do NOT accept yet — wait for DNS to be added
        challenges[chal.Token] = dnsValue
    }
}

	}

	fmt.Println("Waiting for authorization...")

	for _, authURL := range order.AuthzURLs {
		auth, err := client.WaitAuthorization(ctx, authURL)
		if err != nil {
			fmt.Println("Authorization failed:", err)
			return
		}
		fmt.Println("Authorization status:", auth.Status)
	}

	fmt.Println("Authorization valid, creating CSR...")

	csrTemplate := &x509.CertificateRequest{
		DNSNames: []string{domain},
	}

	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)

	certChain, _, _ := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)

	fmt.Println("Certificate issued!")

	for _, cert := range certChain {
		fmt.Println(string(cert))
	}
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
