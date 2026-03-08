package geoip

import (
	"errors"
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

type Resolver interface {
	CountryCode(ip net.IP) (string, error)
}

type MMDBResolver struct {
	reader *geoip2.Reader
}

func NewMMDBResolver(path string) (*MMDBResolver, error) {
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDBResolver{reader: r}, nil
}

func (r *MMDBResolver) CountryCode(ip net.IP) (string, error) {
	if ip == nil {
		return "", errors.New("empty ip")
	}
	rec, err := r.reader.Country(ip)
	if err != nil {
		return "", err
	}
	code := strings.ToUpper(strings.TrimSpace(rec.Country.IsoCode))
	if code == "" {
		return "", errors.New("country not found")
	}
	return code, nil
}

func (r *MMDBResolver) Close() error {
	if r == nil || r.reader == nil {
		return nil
	}
	return r.reader.Close()
}

type NoopResolver struct{}

func (NoopResolver) CountryCode(_ net.IP) (string, error) {
	return "", errors.New("geoip disabled")
}
