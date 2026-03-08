package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"llm_guard/internal/storage/sqlite"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "create":
		if err := runCreate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "revoke":
		if err := runRevoke(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(2)
	}
}

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	dbPath := fs.String("db", "./storage/llm_guard.db", "path to sqlite database")
	name := fs.String("name", "", "human-friendly key name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		*name = fmt.Sprintf("manual-%d", time.Now().Unix())
	}
	rawKey, err := generateAPIKey(32)
	if err != nil {
		return err
	}

	store, closeFn, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeFn()

	if err := store.CreateAPIKey(context.Background(), *name, rawKey); err != nil {
		return err
	}

	fmt.Printf("created api key name=%s\n", *name)
	fmt.Println("WARNING: this is the only time you will see this API key. Copy and store it securely now.")
	fmt.Printf("api_key = %s\n", rawKey)
	return nil
}

func runRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	dbPath := fs.String("db", "./storage/llm_guard.db", "path to sqlite database")
	id := fs.Int64("id", 0, "api key id")
	name := fs.String("name", "", "api key name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *id == 0 && *name == "" {
		return errors.New("provide either -id or -name")
	}

	store, closeFn, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeFn()

	var changed bool
	if *id != 0 {
		changed, err = store.RevokeAPIKeyByID(context.Background(), *id)
	} else {
		changed, err = store.RevokeAPIKeyByName(context.Background(), *name)
	}
	if err != nil {
		return err
	}

	if !changed {
		fmt.Println("no active api key matched")
		return nil
	}

	if *id != 0 {
		fmt.Printf("revoked api key id=%d\n", *id)
	} else {
		fmt.Printf("revoked api key name=%s\n", *name)
	}
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	dbPath := fs.String("db", "./storage/llm_guard.db", "path to sqlite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, closeFn, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeFn()

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tACTIVE\tCREATED_AT\tLAST_USED_AT\tUSAGE_COUNT")
	for _, k := range keys {
		lastUsed := ""
		if k.LastUsedAt != nil {
			lastUsed = k.LastUsedAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(
			tw,
			"%d\t%s\t%s\t%s\t%s\t%d\n",
			k.ID,
			k.Name,
			strconv.FormatBool(k.Active),
			k.CreatedAt.UTC().Format(time.RFC3339),
			lastUsed,
			k.UsageCount,
		)
	}
	return tw.Flush()
}

func openStore(dbPath string) (*sqlite.APIKeyStore, func() error, error) {
	db, err := sqlite.OpenAndInit(dbPath)
	if err != nil {
		return nil, nil, err
	}
	return sqlite.NewAPIKeyStore(db), db.Close, nil
}

func generateAPIKey(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func printUsage() {
	fmt.Println("apikeyctl manages llm_guard API keys")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  apikeyctl create [-db path] [-name value]")
	fmt.Println("  apikeyctl revoke [-db path] (-id value | -name value)")
	fmt.Println("  apikeyctl list   [-db path]")
}
