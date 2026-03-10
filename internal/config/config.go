package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr          string
	DatabasePath        string
	GeoIPDBPath         string
	ClassifierPath      string
	CountryBlacklist    map[string]struct{}
	DomainBlacklistPath string
	InitialAPIKeys      []string
	TrustProxyHeaders   bool
	FailClosed          bool
	RiskThreshold       float64
	MaxBodyBytes        int64
	RateLimitRPS        float64
	RateLimitBurst      int
}

func LoadFromEnv() Config {
	maxBody := int64(getInt("MAX_BODY_BYTES", 1<<20))
	return Config{
		ListenAddr:          getString("LISTEN_ADDR", ":8080"),
		DatabasePath:        getString("DATABASE_PATH", "./storage/llm_guard.db"),
		GeoIPDBPath:         getString("GEOIP_DB_PATH", "./storage/GeoLite2-Country.mmdb"),
		ClassifierPath:      getString("CLASSIFIER_PATH", "./models/classifier_v1.json"),
		CountryBlacklist:    toSetCSV(getString("COUNTRY_BLACKLIST", "")),
		DomainBlacklistPath: getString("DOMAIN_BLACKLIST_PATH", "./config/domain_blacklist.txt"),
		InitialAPIKeys:      toListCSV(getString("INITIAL_API_KEYS", "")),
		TrustProxyHeaders:   getBool("TRUST_PROXY_HEADERS", false),
		FailClosed:          getBool("FAIL_CLOSED", true),
		RiskThreshold:       getFloat("RISK_THRESHOLD", 0.70),
		MaxBodyBytes:        maxBody,
		RateLimitRPS:        getFloat("RATE_LIMIT_RPS", 10),
		RateLimitBurst:      getInt("RATE_LIMIT_BURST", 20),
	}
}

func getString(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return i
}

func getFloat(key string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

func toSetCSV(v string) map[string]struct{} {
	items := toListCSV(v)
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[strings.ToUpper(item)] = struct{}{}
	}
	return set
}

func toListCSV(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
