package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"llm_guard/internal/api"
	"llm_guard/internal/auth"
	"llm_guard/internal/config"
	"llm_guard/internal/geoip"
	"llm_guard/internal/safety"
	"llm_guard/internal/safety/rules"
	"llm_guard/internal/storage/sqlite"
)

func main() {
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
	engine.Register(rules.NewPromptInjectionRule())
	engine.Register(rules.NewExfiltrationRule())
	engine.Register(rules.NewHostTakeoverRule())
	engine.Register(rules.NewCountryBlacklistRule(cfg.CountryBlacklist, cfg.FailClosed))

	router := api.NewRouter(api.Dependencies{
		Config:          cfg,
		Engine:          engine,
		AuthMiddleware:  auth.BearerMiddleware(validator),
		CountryResolver: countryResolver,
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
