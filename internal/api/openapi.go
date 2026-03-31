package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.json
var openAPISpec []byte

//go:embed index.html
var indexHTML []byte

//go:embed llms.txt
var llmsTXT []byte

func serveOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}

func serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func serveLLMsTXT(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(llmsTXT)
}
