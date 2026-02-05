package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/acme"
)

var pendingOrder *acme.Order
var pendingChallenge *acme.Challenge
var pendingAuthURL string
var pendingKey *rsa.PrivateKey
var pendingDomain string
var pendingDNSValue string

type GenerateRequest struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

type GenerateResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DNSName  string `json:"dns_name"`
	DNSValue string `json:"dns_value"`
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	requestCertificate(req.Domain, req.Email)

	response := GenerateResponse{
		Status:   "pending_dns",
		Message:  "Add this TXT record in DNS, then click Finalize",
		DNSName:  "_acme-challenge." + req.Domain,
		DNSValue: pendingDNSValue,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func requestCertificate(domain string, email string) {
	ctx := context.Background()

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	client := &acme.Client{
		Key: privateKey,
		// 🔴 CHANGE TO PRODUCTION WHEN READY
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
	}

	account := &acme.Account{Contact: []string{"mailto:" + email}}
	client.Register(ctx, account, acme.AcceptTOS)

	order, _ := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: domain},
	})

	for _, aURL := range order.AuthzURLs {
		auth, _ := client.GetAuthorization(ctx, aURL)

		for _, chal := range auth.Challenges {
			if chal.Type == "dns-01" {

				pendingOrder = order
				pendingChallenge = chal
				pendingAuthURL = aURL
				pendingKey = privateKey
				pendingDomain = domain

				dnsValue, _ := client.DNS01ChallengeRecord(chal.Token)
				pendingDNSValue = dnsValue

				fmt.Println("=================================")
				fmt.Println("ADD THIS DNS RECORD:")
				fmt.Println("Name: _acme-challenge." + domain)
				fmt.Println("TXT Value:", dnsValue)
				fmt.Println("=================================")
			}
		}
	}

	fmt.Println("DNS challenge prepared.")
}

func finalizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	client := &acme.Client{
		Key:          pendingKey,
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
	}

	fmt.Println("Accepting DNS challenge...")
	client.Accept(ctx, pendingChallenge)

	fmt.Println("Waiting for authorization...")
	auth, err := client.WaitAuthorization(ctx, pendingAuthURL)
	if err != nil {
		fmt.Println("Authorization failed:", err)
		http.Error(w, "Authorization failed: "+err.Error(), 500)
		return
	}
	fmt.Println("Authorization status:", auth.Status)

	fmt.Println("Creating CSR...")
	csrTemplate := &x509.CertificateRequest{
		DNSNames: []string{pendingDomain},
	}

	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, pendingKey)

	certChain, _, _ := client.CreateOrderCert(ctx, pendingOrder.FinalizeURL, csrDER, true)

	os.MkdirAll("certs/"+pendingDomain, 0700)

	certFile := "certs/" + pendingDomain + "/cert.pem"
	keyFile := "certs/" + pendingDomain + "/key.pem"

	os.WriteFile(certFile, certChain[0], 0600)

	keyBytes := x509.MarshalPKCS1PrivateKey(pendingKey)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600)

	fmt.Println("🎉 CERTIFICATE SAVED 🎉")

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Certificate issued and saved successfully!"))
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	http.ServeFile(w, r, "certs/"+domain+"/cert.pem")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Serve UI
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)

	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/finalize", finalizeHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("Server running on port", port)
	http.ListenAndServe(":"+port, nil)
}
