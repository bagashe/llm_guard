package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"llm_guard/internal/api"
	"llm_guard/internal/auth"
	"llm_guard/internal/classifier"
	"llm_guard/internal/config"
	"llm_guard/internal/geoip"
	"llm_guard/internal/ratelimit"
	"llm_guard/internal/safety"
	"llm_guard/internal/safety/rules"
	"llm_guard/internal/storage/sqlite"
)

func main() {
	_ = godotenv.Load()

	cfg := config.LoadFromEnv()

	db, err := sqlite.OpenAndInit(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	keyStore := sqlite.NewAPIKeyStore(db)
	if err := keyStore.BootstrapKeys(context.Background(), cfg.InitialAPIKeys); err != nil {
		log.Fatalf("bootstrap api keys: %v", err)
	}

	validator := auth.NewValidator(keyStore)

	var countryResolver geoip.Resolver
	if cfg.GeoIPDBPath != "" {
		resolver, err := geoip.NewMMDBResolver(cfg.GeoIPDBPath)
		if err != nil {
			log.Fatalf("open geoip db: %v", err)
		}
		defer resolver.Close()
		countryResolver = resolver
	} else {
		countryResolver = geoip.NoopResolver{}
	}

	engine := safety.NewEngine(cfg.FailClosed, cfg.RiskThreshold)
	engine.Register(rules.NewCountryBlacklistRule(cfg.CountryBlacklist, cfg.FailClosed))
	if cfg.ClassifierPath == "" {
		log.Fatal("classifier path is required")
	}
	clf, err := classifier.Load(cfg.ClassifierPath)
	if err != nil {
		log.Fatalf("load classifier path=%s: %v", cfg.ClassifierPath, err)
	}
	engine.Register(rules.NewClassifierRule(clf))
	log.Printf("classifier loaded path=%s labels=%d", cfg.ClassifierPath, len(clf.Labels))
	engine.Register(rules.NewPIIDetectionRule())
	log.Println("input scanning rule registered: pii_detection")
	engine.Register(rules.NewSystemPromptLeakRule())
	engine.Register(rules.NewSecretLeakRule())
	log.Println("output scanning rules registered: system_prompt_leak, secret_leak")

	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitBurst, 10*time.Minute)
	defer limiter.Stop()
	log.Printf("rate limiter enabled rps=%.1f burst=%d", cfg.RateLimitRPS, cfg.RateLimitBurst)

	router := api.NewRouter(api.Dependencies{
		Config:              cfg,
		Engine:              engine,
		AuthMiddleware:      auth.BearerMiddleware(validator),
		RateLimitMiddleware: limiter.Middleware,
		CountryResolver:     countryResolver,
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
