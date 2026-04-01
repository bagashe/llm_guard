package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/joho/godotenv"

	"llm_guard/internal/storage/sqlite"
)

func main() {
	_ = godotenv.Load()

	if len(os.Args) < 3 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "messages":
		switch os.Args[2] {
		case "list":
			if err := runList(os.Args[3:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		case "reply":
			if err := runReply(os.Args[3:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
		default:
			printUsage()
			os.Exit(2)
		}
	default:
		printUsage()
		os.Exit(2)
	}
}

func runList(args []string) error {
	fs := flag.NewFlagSet("messages list", flag.ContinueOnError)
	dbPath := fs.String("db", "./storage/llm_guard.db", "path to sqlite database")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, closeFn, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeFn()

	msgs, err := store.ListAllAgentMessages(context.Background())
	if err != nil {
		return err
	}

	if len(msgs) == 0 {
		fmt.Println("no messages")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKEY_NAME\tCREATED_AT\tMESSAGE")
	for _, m := range msgs {
		msg := m.Message
		if len(msg) > 80 {
			msg = msg[:77] + "..."
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n",
			m.ID,
			m.KeyName,
			m.CreatedAt.UTC().Format(time.RFC3339),
			msg,
		)
	}
	return tw.Flush()
}

func runReply(args []string) error {
	fs := flag.NewFlagSet("messages reply", flag.ContinueOnError)
	dbPath := fs.String("db", "./storage/llm_guard.db", "path to sqlite database")
	name := fs.String("name", "", "key name of the agent to reply to")
	message := fs.String("message", "", "message text to send")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	if *message == "" {
		return fmt.Errorf("-message is required")
	}

	store, closeFn, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeFn()

	if err := store.CreateInboxMessage(context.Background(), *name, *message); err != nil {
		return err
	}

	fmt.Printf("message sent to agent name=%s\n", *name)
	return nil
}

func openStore(dbPath string) (*sqlite.APIKeyStore, func() error, error) {
	db, err := sqlite.OpenAndInit(dbPath)
	if err != nil {
		return nil, nil, err
	}
	return sqlite.NewAPIKeyStore(db), db.Close, nil
}

func printUsage() {
	fmt.Println("msgctl manages agent messages in llm_guard")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  msgctl messages list   [-db path]")
	fmt.Println("  msgctl messages reply  [-db path] -name KEY_NAME -message TEXT")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  messages list    List all messages received from agents.")
	fmt.Println("  messages reply   Send a message to an agent's inbox (identified by key name).")
}
