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
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

/* =======================
   GLOBAL STATE (SINGLE JOB)
   ======================= */

var (
	mu               sync.Mutex
	pendingOrder     *acme.Order
	pendingChallenge *acme.Challenge
	pendingAuthURL   string
	pendingKey       *rsa.PrivateKey
	pendingDomain    string
	pendingDNSValue  string
)

/* =======================
   REQUEST / RESPONSE TYPES
   ======================= */

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

/* =======================
   HANDLERS
   ======================= */

func generateHandler(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	dnsName, dnsValue, err := prepareDNSChallenge(req.Domain, req.Email)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	resp := GenerateResponse{
		Status:   "pending_dns",
		Message:  "Add this TXT record in DNS, then click Finalize",
		DNSName:  dnsName,
		DNSValue: dnsValue,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func finalizeHandler(w http.ResponseWriter, r *http.Request) {
	go completeIssuance()
	w.Write([]byte("Finalization started. Certificate will be generated shortly."))
}

func downloadCert(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	http.ServeFile(w, r, "certs/"+domain+"/cert.pem")
}

func downloadKey(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	http.ServeFile(w, r, "certs/"+domain+"/private-key.pem")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`{"status":"ok"}`))
}

/* =======================
   ACME CORE LOGIC
   ======================= */

func prepareDNSChallenge(domain, email string) (string, string, error) {
	ctx := context.Background()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	client := &acme.Client{
		Key:          key,
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
	}

	client.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + email},
	}, acme.AcceptTOS)

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: domain},
	})
	if err != nil {
		return "", "", err
	}

	for _, authURL := range order.AuthzURLs {
		auth, _ := client.GetAuthorization(ctx, authURL)
		for _, chal := range auth.Challenges {
			if chal.Type == "dns-01" {
				dnsValue, _ := client.DNS01ChallengeRecord(chal.Token)

				mu.Lock()
				pendingOrder = order
				pendingChallenge = chal
				pendingAuthURL = authURL
				pendingKey = key
				pendingDomain = domain
				pendingDNSValue = dnsValue
				mu.Unlock()

				return "_acme-challenge." + domain, dnsValue, nil
			}
		}
	}

	return "", "", fmt.Errorf("no dns challenge found")
}

func completeIssuance() {
	time.Sleep(5 * time.Second)

	mu.Lock()
	order := pendingOrder
	chal := pendingChallenge
	authURL := pendingAuthURL
	accountKey := pendingKey
	domain := pendingDomain
	mu.Unlock()

	ctx := context.Background()

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
	}

	fmt.Println("Accepting DNS challenge...")
	client.Accept(ctx, chal)

	fmt.Println("Waiting for authorization...")
	if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
		fmt.Println("Authorization failed:", err)
		return
	}

	fmt.Println("Authorization valid. Generating certificate key...")

	// 🔑 NEW KEY FOR CERTIFICATE
	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)

	fmt.Println("Finalizing order...")

	certChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		fmt.Println("Cert creation failed:", err)
		return
	}

	fmt.Println("Saving certificate files...")

	os.MkdirAll("certs/"+domain, 0700)

	os.WriteFile("certs/"+domain+"/cert.pem", certChain[0], 0600)

	keyBytes := x509.MarshalPKCS1PrivateKey(certKey)
	os.WriteFile("certs/"+domain+"/private-key.pem",
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), 0600)

	fmt.Println("🎉 CERTIFICATE GENERATED SUCCESSFULLY 🎉")
}

/* =======================
   MAIN
   ======================= */

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", http.FileServer(http.Dir("static")))

	http.HandleFunc("/generate", generateHandler)
	http.HandleFunc("/finalize", finalizeHandler)
	http.HandleFunc("/download-cert", downloadCert)
	http.HandleFunc("/download-key", downloadKey)
	http.HandleFunc("/health", healthHandler)

	fmt.Println("Server running on port", port)
	http.ListenAndServe(":"+port, nil)
}
