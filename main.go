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
		fmt.Println("JSON decode error:", err)
		http.Error(w, "Invalid request", 400)
		return
	}

	fmt.Println("Starting DNS challenge for:", req.Domain)

	dnsName, dnsValue, err := prepareDNSChallenge(req.Domain, req.Email)
	if err != nil {
		fmt.Println("ACME ERROR:", err)
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
	w.Header().Set("Content-Disposition", "attachment; filename=cert.pem")
	w.Header().Set("Content-Type", "application/x-pem-file")
	http.ServeFile(w, r, "certs/"+domain+"/cert.pem")
}

func downloadKey(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	w.Header().Set("Content-Disposition", "attachment; filename=private-key.pem")
	w.Header().Set("Content-Type", "application/x-pem-file")
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

	if order == nil {
		fmt.Println("No pending order")
		return
	}

	fmt.Println("Saving certificate files...")

	os.MkdirAll("certs/"+domain, 0700)

	// Save domain certificate
	certOut, _ := os.Create("certs/" + domain + "/cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certChain[0]})
	certOut.Close()

	// Save CA bundle (intermediate)
	caOut, _ := os.Create("certs/" + domain + "/cabundle.pem")
	pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: certChain[1]})
	caOut.Close()

	// Save full chain
	fullOut, _ := os.Create("certs/" + domain + "/fullchain.pem")
	pem.Encode(fullOut, &pem.Block{Type: "CERTIFICATE", Bytes: certChain[0]})
	pem.Encode(fullOut, &pem.Block{Type: "CERTIFICATE", Bytes: certChain[1]})
	fullOut.Close()

	// Save private key
	keyBytes := x509.MarshalPKCS1PrivateKey(certKey)
	os.WriteFile("certs/"+domain+"/private-key.pem",
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}), 0600)

	fmt.Println("🎉 CERTIFICATE + CA BUNDLE GENERATED 🎉")

}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "yourpassword" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

/*
=======================

	Download Bundle
	=======================
*/
func downloadBundle(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	w.Header().Set("Content-Disposition", "attachment; filename=cabundle.pem")
	http.ServeFile(w, r, "certs/"+domain+"/cabundle.pem")
}

/*
=======================

	HTTPS handling
	=======================
*/
func allowCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

/* =======================
   MAIN
   ======================= */

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	/* =======================
	   ROUTES
	   ======================= */

	// Public UI
	http.Handle("/", http.FileServer(http.Dir("static")))

	// Protected API
	http.HandleFunc("/generate", allowCORS(basicAuth(generateHandler)))
	http.HandleFunc("/finalize", allowCORS(basicAuth(finalizeHandler)))
	http.HandleFunc("/download-cert", allowCORS(basicAuth(downloadCert)))
	http.HandleFunc("/download-key", allowCORS(basicAuth(downloadKey)))
	http.HandleFunc("/download-bundle", allowCORS(basicAuth(downloadBundle)))

	http.HandleFunc("/health", healthHandler)

	fmt.Println("Server running on port", port)
	http.ListenAndServe(":"+port, nil)
}
