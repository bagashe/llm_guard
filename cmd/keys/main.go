package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"

	"llm_guard/internal/storage/sqlite"
)

// mode represents the current interaction state.
type mode int

const (
	modeBrowse        mode = iota
	modeNewKeyName         // user is typing a name for a new key
	modeSetQuota           // user is typing a new daily quota
	modeConfirmRevoke      // user is confirming a revoke
)

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#5fdfb0")).
			PaddingBottom(1)

	rightPaneStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderLeft(true).
			BorderForeground(lipgloss.Color("#333333")).
			Padding(0, 1)

	detailLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#5fdfb0")).
				Bold(true)

	detailMetaStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	detailFieldKeyStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#666666")).
				Width(12)

	detailFieldValStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#cccccc"))

	newKeyWarningStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffcc00")).
				Bold(true)

	newKeyValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffffff")).
				Background(lipgloss.Color("#1e1e1e")).
				Padding(0, 1)

	revokedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	emptyDetailStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#444444"))

	hrStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#2a2a2a"))

	actionPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5fdfb0")).
			Padding(0, 1)

	confirmPaneStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#ff5555")).
				Padding(0, 1)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444444"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff5555"))
)

// ---------------------------------------------------------------------------
// List item
// ---------------------------------------------------------------------------

type keyItem struct {
	key sqlite.APIKeyRecord
}

func (i keyItem) Title() string {
	if !i.key.Active {
		return revokedStyle.Render(i.key.Name + "  [revoked]")
	}
	return i.key.Name
}

func (i keyItem) Description() string {
	quota := "unlimited"
	if i.key.DailyLimit != nil {
		quota = fmt.Sprintf("%d/day", *i.key.DailyLimit)
	}
	return fmt.Sprintf("#%d  ·  %d uses  ·  quota: %s", i.key.ID, i.key.UsageCount, quota)
}

func (i keyItem) FilterValue() string { return i.key.Name }

// ---------------------------------------------------------------------------
// tea.Msg types
// ---------------------------------------------------------------------------

type secondTickMsg time.Time

type refreshedMsg []sqlite.APIKeyRecord
type refreshErrMsg error

type keyCreatedMsg struct{ name, raw string }
type keyCreateErrMsg error

type keyRevokedMsg struct{}
type keyRevokeErrMsg error

type quotaSetMsg struct{}
type quotaSetErrMsg error

type quotaClearedMsg struct{}
type quotaClearErrMsg error

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type model struct {
	list        list.Model
	keys        []sqlite.APIKeyRecord
	mode        mode
	input       textinput.Model
	store       *sqlite.APIKeyStore
	statusMsg   string
	lastRefresh time.Time
	nextRefresh time.Time
	width       int
	height      int
	err         error
	newKeyName  string // name of the just-created key
	newKeyRaw   string // raw value shown once after creation
}

func newModel(store *sqlite.APIKeyStore) model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	l := list.New(nil, delegate, 0, 0)
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	ti := textinput.New()
	ti.CharLimit = 64

	return model{list: l, input: ti, store: store, nextRefresh: time.Now().Add(60 * time.Second)}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func (m model) Init() tea.Cmd {
	return tea.Batch(fetchKeys(m.store), tickEverySecond())
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return secondTickMsg(t) })
}

func fetchKeys(store *sqlite.APIKeyStore) tea.Cmd {
	return func() tea.Msg {
		keys, err := store.ListAPIKeys(context.Background())
		if err != nil {
			return refreshErrMsg(err)
		}
		return refreshedMsg(keys)
	}
}

func doCreateKey(store *sqlite.APIKeyStore, name string) tea.Cmd {
	return func() tea.Msg {
		raw, err := generateAPIKey(32)
		if err != nil {
			return keyCreateErrMsg(err)
		}
		if err := store.CreateAPIKey(context.Background(), name, raw); err != nil {
			return keyCreateErrMsg(err)
		}
		return keyCreatedMsg{name: name, raw: raw}
	}
}

func doRevokeKey(store *sqlite.APIKeyStore, id int64) tea.Cmd {
	return func() tea.Msg {
		if _, err := store.RevokeAPIKeyByID(context.Background(), id); err != nil {
			return keyRevokeErrMsg(err)
		}
		return keyRevokedMsg{}
	}
}

func doSetQuota(store *sqlite.APIKeyStore, id, limit int64) tea.Cmd {
	return func() tea.Msg {
		if err := store.SetDailyQuotaByID(context.Background(), id, limit); err != nil {
			return quotaSetErrMsg(err)
		}
		return quotaSetMsg{}
	}
}

func doClearQuota(store *sqlite.APIKeyStore, id int64) tea.Cmd {
	return func() tea.Msg {
		if err := store.ClearDailyQuotaByID(context.Background(), id); err != nil {
			return quotaClearErrMsg(err)
		}
		return quotaClearedMsg{}
	}
}

func generateAPIKey(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		m.input.Width = msg.Width - 8
		return m, nil

	case secondTickMsg:
		cmds := []tea.Cmd{tickEverySecond()}
		if !time.Time(msg).Before(m.nextRefresh) {
			m.nextRefresh = time.Time(msg).Add(60 * time.Second)
			cmds = append(cmds, fetchKeys(m.store))
		}
		return m, tea.Batch(cmds...)

	case refreshedMsg:
		m.keys = []sqlite.APIKeyRecord(msg)
		m.lastRefresh = time.Now()
		m.newKeyRaw = ""
		m.newKeyName = ""
		m.err = nil
		idx := m.list.Index()
		items := make([]list.Item, len(m.keys))
		for i, k := range m.keys {
			items[i] = keyItem{k}
		}
		m.list.SetItems(items)
		if idx < len(items) {
			m.list.Select(idx)
		}
		return m, nil

	case refreshErrMsg:
		m.err = error(msg)
		return m, nil

	case keyCreatedMsg:
		m.newKeyName = msg.name
		m.newKeyRaw = msg.raw
		m.statusMsg = fmt.Sprintf("Key %q created — copy the key shown on the right.", msg.name)
		m.err = nil
		return m, fetchKeys(m.store)

	case keyCreateErrMsg:
		m.err = error(msg)
		return m, nil

	case keyRevokedMsg:
		m.statusMsg = "Key revoked."
		m.err = nil
		return m, fetchKeys(m.store)

	case keyRevokeErrMsg:
		m.err = error(msg)
		return m, nil

	case quotaSetMsg:
		m.statusMsg = "Quota updated."
		m.err = nil
		return m, fetchKeys(m.store)

	case quotaSetErrMsg:
		m.err = error(msg)
		return m, nil

	case quotaClearedMsg:
		m.statusMsg = "Quota cleared."
		m.err = nil
		return m, fetchKeys(m.store)

	case quotaClearErrMsg:
		m.err = error(msg)
		return m, nil

	case tea.KeyMsg:
		switch m.mode {
		case modeNewKeyName, modeSetQuota:
			return m.updateInput(msg)
		case modeConfirmRevoke:
			return m.updateConfirmRevoke(msg)
		default:
			return m.updateBrowse(msg)
		}
	}

	if m.mode == modeBrowse {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) updateBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "r", "R":
		m.newKeyRaw = ""
		m.newKeyName = ""
		m.nextRefresh = time.Now().Add(60 * time.Second)
		return m, fetchKeys(m.store)

	case "n":
		m.mode = modeNewKeyName
		m.input.Placeholder = "e.g. my-agent"
		m.input.SetValue("")
		m.input.Focus()
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, textinput.Blink

	case "x":
		item, ok := m.list.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		m.mode = modeConfirmRevoke
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, nil

	case "s":
		item, ok := m.list.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		current := ""
		if item.key.DailyLimit != nil {
			current = strconv.FormatInt(*item.key.DailyLimit, 10)
		}
		m.mode = modeSetQuota
		m.input.Placeholder = "requests per day"
		m.input.SetValue(current)
		m.input.Focus()
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, textinput.Blink

	case "c":
		item, ok := m.list.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		return m, doClearQuota(m.store, item.key.ID)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case "esc":
		m.mode = modeBrowse
		m.input.SetValue("")
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, nil

	case "enter":
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			return m, nil
		}
		currentMode := m.mode
		m.mode = modeBrowse
		m.input.SetValue("")
		m.list.SetSize(m.leftWidth(), m.contentHeight())

		switch currentMode {
		case modeNewKeyName:
			return m, doCreateKey(m.store, val)

		case modeSetQuota:
			item, ok := m.list.SelectedItem().(keyItem)
			if !ok {
				return m, nil
			}
			limit, err := strconv.ParseInt(val, 10, 64)
			if err != nil || limit <= 0 {
				m.err = fmt.Errorf("invalid quota %q: must be a positive integer", val)
				return m, nil
			}
			return m, doSetQuota(m.store, item.key.ID, limit)
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) updateConfirmRevoke(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "n", "N":
		m.mode = modeBrowse
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, nil
	case "y", "Y":
		item, ok := m.list.SelectedItem().(keyItem)
		m.mode = modeBrowse
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		if !ok {
			return m, nil
		}
		return m, doRevokeKey(m.store, item.key.ID)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Header
	activeCount := 0
	for _, k := range m.keys {
		if k.Active {
			activeCount++
		}
	}
	refreshStr := "never"
	if !m.lastRefresh.IsZero() {
		refreshStr = m.lastRefresh.Format("15:04:05")
	}
	countdown := int(time.Until(m.nextRefresh).Seconds()) + 1
	if countdown < 0 {
		countdown = 0
	}
	header := fmt.Sprintf(
		"KEYS  ·  %d active (%d total)  ·  refreshed %s  ·  next in %ds  ·  [n] new  [r] refresh  [q] quit",
		activeCount, len(m.keys), refreshStr, countdown,
	)
	b.WriteString(headerStyle.Render(header))
	b.WriteString(hrStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	// Split pane: list (left) | detail (right)
	// right pane overhead: 1 (border) + 1 (pad-left) + 1 (pad-right) = 3
	contentH := m.contentHeight()
	leftW := m.leftWidth()
	rightInnerW := m.width - leftW - 3

	leftPane := lipgloss.NewStyle().Width(leftW).Height(contentH).Render(m.list.View())
	rightPane := rightPaneStyle.Width(rightInnerW).Height(contentH).Render(m.renderDetail(rightInnerW))

	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane))

	// Action pane (non-browse modes)
	switch m.mode {
	case modeNewKeyName:
		b.WriteString("\n")
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render("New key — enter a name"),
			m.input.View(),
			hintStyle.Render("[enter] create  ·  [esc] cancel"),
		)
		b.WriteString(actionPaneStyle.Width(m.width - 2).Render(inner))

	case modeSetQuota:
		b.WriteString("\n")
		item, _ := m.list.SelectedItem().(keyItem)
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render(
				fmt.Sprintf("Daily quota for %s (requests/day)", item.key.Name),
			),
			m.input.View(),
			hintStyle.Render("[enter] save  ·  [esc] cancel"),
		)
		b.WriteString(actionPaneStyle.Width(m.width - 2).Render(inner))

	case modeConfirmRevoke:
		b.WriteString("\n")
		item, _ := m.list.SelectedItem().(keyItem)
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff5555")).
				Render(fmt.Sprintf("Revoke %q?", item.key.Name)),
			hintStyle.Render("This cannot be undone."),
			hintStyle.Render("[y] confirm  ·  [esc / n] cancel"),
		)
		b.WriteString(confirmPaneStyle.Width(m.width - 2).Render(inner))
	}

	// Status / error line
	b.WriteString("\n")
	if m.err != nil {
		b.WriteString(errorStyle.Render("error: " + m.err.Error()))
	} else if m.statusMsg != "" {
		b.WriteString(statusStyle.Render(m.statusMsg))
	}

	return b.String()
}

// renderDetail renders the right-hand key detail pane.
func (m model) renderDetail(w int) string {
	item, ok := m.list.SelectedItem().(keyItem)
	if !ok {
		return emptyDetailStyle.Render("select a key to see details")
	}
	k := item.key

	// One-time new key display
	if m.newKeyRaw != "" && m.newKeyName == k.Name {
		return m.renderNewKey(k, w)
	}

	activeStr := detailFieldValStyle.Render("active")
	if !k.Active {
		activeStr = revokedStyle.Render("revoked")
	}

	lastUsed := "never"
	if k.LastUsedAt != nil {
		lastUsed = k.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC")
	}

	quota := "unlimited"
	if k.DailyLimit != nil {
		quota = fmt.Sprintf("%d/day  (%d used today)", *k.DailyLimit, k.DailyCount)
	}

	field := func(key, val string) string {
		return lipgloss.JoinHorizontal(lipgloss.Top,
			detailFieldKeyStyle.Render(key),
			detailFieldValStyle.Render(val),
		)
	}

	lines := []string{
		detailLabelStyle.Render(k.Name),
		detailMetaStyle.Render(fmt.Sprintf("#%d  ·  %s", k.ID, activeStr)),
		"",
		field("created", k.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")),
		field("last used", lastUsed),
		field("total uses", strconv.FormatInt(k.UsageCount, 10)),
		field("quota", quota),
	}

	if k.Active {
		lines = append(lines, "",
			hintStyle.Render("[x] revoke  ·  [s] set quota  ·  [c] clear quota"),
		)
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderNewKey shows the raw key value prominently (one-time display).
func (m model) renderNewKey(k sqlite.APIKeyRecord, w int) string {
	return lipgloss.JoinVertical(lipgloss.Left,
		detailLabelStyle.Render(k.Name+"  — created"),
		"",
		newKeyWarningStyle.Render("API key (shown once — copy now):"),
		"",
		newKeyValueStyle.Width(w).Render(m.newKeyRaw),
		"",
		hintStyle.Render("press [r] or navigate away to dismiss"),
	)
}

// ---------------------------------------------------------------------------
// Layout helpers
// ---------------------------------------------------------------------------

func (m model) leftWidth() int {
	w := m.width * 38 / 100
	if w < 28 {
		w = 28
	}
	return w
}

func (m model) contentHeight() int {
	h := m.height
	h -= 2 // header + PaddingBottom
	h -= 1 // status line
	if m.mode != modeBrowse {
		h -= 6 // \n + action pane (border×2 + label + input + hint)
	}
	if h < 1 {
		h = 1
	}
	return h
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	_ = godotenv.Load()

	dbPath := flag.String("db", "./storage/llm_guard.db", "path to sqlite database")
	flag.Parse()

	db, err := sqlite.OpenAndInit(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening database:", err)
		os.Exit(1)
	}
	defer db.Close()

	store := sqlite.NewAPIKeyStore(db)

	p := tea.NewProgram(newModel(store), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
