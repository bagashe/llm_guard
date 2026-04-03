package main

import (
	"context"
	"io"
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
	"llm_guard/internal/registration"
	"llm_guard/internal/safety"
	"llm_guard/internal/safety/rules"
	"llm_guard/internal/storage/sqlite"
)

func main() {
	_ = godotenv.Load()

	cfg := config.LoadFromEnv()
	if cfg.LogFilePath != "" {
		lf, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("open log file: %v", err)
		}
		defer lf.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}
	if cfg.Debug {
		log.Println("WARNING: DEBUG=true enables verbose request audit logging (tool_args and safety fields); disable in production")
	}
	debugf := func(format string, args ...any) {
		if cfg.Debug {
			log.Printf(format, args...)
		}
	}

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
	debugf("geo rules registered: country_blacklist.blocked_country,country_blacklist.unknown_country")
	domainBlacklist, err := config.LoadDomainBlacklist(cfg.DomainBlacklistPath)
	if err != nil {
		log.Fatalf("load domain blacklist path=%s: %v", cfg.DomainBlacklistPath, err)
	}
	internalAllowlist, err := config.LoadInternalDestinationAllowlist(cfg.InternalAllowlistPath)
	if err != nil {
		log.Fatalf("load internal destination allowlist path=%s: %v", cfg.InternalAllowlistPath, err)
	}
	engine.Register(rules.NewToolCallDomainBlacklistRule(domainBlacklist))
	engine.Register(rules.NewToolCallInternalNetworkAccessRule(internalAllowlist.Domains, internalAllowlist.IPs, internalAllowlist.CIDRs))
	engine.Register(rules.NewToolCallRedirectResolutionRule(domainBlacklist, internalAllowlist.Domains, internalAllowlist.IPs, internalAllowlist.CIDRs))
	engine.Register(rules.NewToolCallCommandPolicyRule())
	engine.Register(rules.NewToolCallSQLPolicyRule())
	debugf("tool-call rules registered: tool_call.domain_blacklist,tool_call.internal_network_access,tool_call.redirect_resolution,tool_call.command_policy,tool_call.sql_policy domains=%d internal_allowlist_domains=%d internal_allowlist_ips=%d internal_allowlist_cidrs=%d", len(domainBlacklist), len(internalAllowlist.Domains), len(internalAllowlist.IPs), len(internalAllowlist.CIDRs))
	if cfg.ClassifierPath == "" {
		log.Fatal("classifier path is required")
	}
	clf, err := classifier.Load(cfg.ClassifierPath)
	if err != nil {
		log.Fatalf("load classifier path=%s: %v", cfg.ClassifierPath, err)
	}
	debugf("classifier loaded path=%s labels=%d", cfg.ClassifierPath, len(clf.Labels))
	if cfg.WordClassifierPath == "" {
		log.Fatal("word classifier path is required")
	}
	wordClf, err := classifier.Load(cfg.WordClassifierPath)
	if err != nil {
		log.Fatalf("load word classifier path=%s: %v", cfg.WordClassifierPath, err)
	}
	debugf("word classifier loaded path=%s labels=%d", cfg.WordClassifierPath, len(wordClf.Labels))
	engine.Register(rules.NewClassifierRule(clf, wordClf))
	debugf("input rules registered: classifier.malicious_intent,input.pii_detection")
	engine.Register(rules.NewPIIDetectionRule())
	engine.Register(rules.NewSystemPromptLeakRule())
	engine.Register(rules.NewSecretLeakRule())
	debugf("output rules registered: output.system_prompt_leak,output.secret_leak")

	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitBurst, 10*time.Minute)
	defer limiter.Stop()
	debugf("rate limiter enabled rps=%.1f burst=%d", cfg.RateLimitRPS, cfg.RateLimitBurst)

	var challengeStore *registration.ChallengeStore
	var keyCreator registration.KeyCreator
	if cfg.RegistrationEnabled {
		challengeStore = registration.NewChallengeStore(cfg.RegistrationDifficulty)
		defer challengeStore.Stop()
		keyCreator = keyStore
		debugf("self-registration enabled difficulty=%d daily_limit=%d",
			cfg.RegistrationDifficulty, cfg.RegistrationDefaultDailyLimit)
	}

	router := api.NewRouter(api.Dependencies{
		Config:              cfg,
		Engine:              engine,
		AuthMiddleware:      auth.BearerMiddleware(validator),
		RateLimitMiddleware: limiter.Middleware,
		CountryResolver:     countryResolver,
		ChallengeStore:      challengeStore,
		KeyCreator:          keyCreator,
		MessageStore:        keyStore,
		ToolPolicyChecker:   keyStore,
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
		debugf("listening on %s", cfg.ListenAddr)
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
