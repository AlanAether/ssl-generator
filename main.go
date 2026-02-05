package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

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

	response := GenerateResponse{
		Status:  "success",
		Message: "Pretend SSL certificate generated for " + req.Domain,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/generate", generateHandler)

	fmt.Println("Server running on port", port)
	http.ListenAndServe(":"+port, nil)
}
