package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"
	"github.com/muesli/reflow/wordwrap"

	"llm_guard/internal/storage/sqlite"
)

// ---------------------------------------------------------------------------
// Tabs and keys-tab mode
// ---------------------------------------------------------------------------

type tab int

const (
	tabKeys  tab = iota // 0
	tabInbox            // 1
	tabLogs             // 2
)

type keysMode int

const (
	keysBrowse        keysMode = iota
	keysNewKeyName             // user typing a name for a new key
	keysSetQuota               // user typing a daily quota
	keysConfirmRevoke          // user confirming a revoke
)

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	// Active tab: filled pill (dark text on teal background).
	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0d0d0d")).
			Background(lipgloss.Color("#5fdfb0")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#aaaaaa")).
				Padding(0, 1)

	changedTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffcc00")).
				Padding(0, 1)

	brandStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#5fdfb0"))

	rightPaneStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderLeft(true).
			BorderForeground(lipgloss.Color("#444444")).
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

	detailBodyStyle = lipgloss.NewStyle().
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
		Foreground(lipgloss.Color("#444444"))

	actionPaneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5fdfb0")).
			Padding(0, 1)

	confirmPaneStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#ff5555")).
				Padding(0, 1)

	replyBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#5fdfb0")).
				Padding(0, 1)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444444"))

	// statusBarStyle and errorBarStyle render as a full-width strip at the
	// bottom of each tab. Width is set at the call site.
	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#111111")).
			Foreground(lipgloss.Color("#999999")).
			Padding(0, 1)

	errorBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#111111")).
			Foreground(lipgloss.Color("#ff5555")).
			Padding(0, 1)

	logLineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#aaaaaa"))

	logNoFileStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))
)

// ---------------------------------------------------------------------------
// List items
// ---------------------------------------------------------------------------

type keyItem struct{ key sqlite.APIKeyRecord }

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

type msgItem struct{ msg sqlite.AgentMessageWithKeyName }

func (i msgItem) Title() string { return i.msg.KeyName }
func (i msgItem) Description() string {
	return fmt.Sprintf("#%d · %s", i.msg.ID, i.msg.CreatedAt.UTC().Format("2006-01-02 15:04"))
}
func (i msgItem) FilterValue() string { return i.msg.KeyName }

// ---------------------------------------------------------------------------
// tea.Msg types
// ---------------------------------------------------------------------------

type secondTickMsg time.Time

// Keys tab messages.
type keysRefreshedMsg []sqlite.APIKeyRecord
type keysRefreshErrMsg error
type keyCreatedMsg struct{ name, raw string }
type keyCreateErrMsg error
type keyRevokedMsg struct{}
type keyRevokeErrMsg error
type quotaSetMsg struct{}
type quotaSetErrMsg error
type quotaClearedMsg struct{}
type quotaClearErrMsg error

// Inbox tab messages.
type inboxRefreshedMsg []sqlite.AgentMessageWithKeyName
type inboxRefreshErrMsg error
type replySentMsg struct{}
type replyErrMsg error

// Logs tab messages.
type logPollMsg struct {
	lines     []string
	newOffset int64
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

const maxLogLines = 2000

type model struct {
	activeTab tab
	width     int
	height    int
	store     *sqlite.APIKeyStore

	// Keys tab state.
	keysList        list.Model
	keysKeys        []sqlite.APIKeyRecord
	keysMode        keysMode
	keysInput       textinput.Model
	keysStatusMsg   string
	keysLastRefresh time.Time
	keysNextRefresh time.Time
	keysErr         error
	keysNewKeyName  string
	keysNewKeyRaw   string

	// Inbox tab state.
	inboxList        list.Model
	inboxMessages    []sqlite.AgentMessageWithKeyName
	inboxReplying    bool
	inboxSelected    *sqlite.AgentMessageWithKeyName
	inboxTextarea    textarea.Model
	inboxStatusMsg   string
	inboxLastRefresh time.Time
	inboxNextRefresh time.Time
	inboxErr         error

	// Logs tab state.
	logLines  []string
	logPath   string
	logOffset int64

	// Per-tab change indicators: set when content changes while the user is
	// on a different tab, cleared when the user switches to that tab.
	keysChanged  bool
	inboxChanged bool
	logsChanged  bool
}

func newModel(store *sqlite.APIKeyStore, logPath string) model {
	makeList := func() list.Model {
		delegate := list.NewDefaultDelegate()
		delegate.ShowDescription = true

		// Override the default magenta selection with teal to match the scheme.
		selBorder := lipgloss.Border{Left: "▌"}
		delegate.Styles.SelectedTitle = lipgloss.NewStyle().
			Border(selBorder, false, false, false, true).
			BorderForeground(lipgloss.Color("#5fdfb0")).
			Foreground(lipgloss.Color("#5fdfb0")).
			Bold(true).
			Padding(0, 0, 0, 1)
		delegate.Styles.SelectedDesc = lipgloss.NewStyle().
			Border(selBorder, false, false, false, true).
			BorderForeground(lipgloss.Color("#5fdfb0")).
			Foreground(lipgloss.Color("#3d8f6a")).
			Padding(0, 0, 0, 1)

		l := list.New(nil, delegate, 0, 0)
		l.SetShowTitle(false)
		l.SetShowHelp(false)
		l.SetShowStatusBar(false)
		l.SetFilteringEnabled(false)
		return l
	}

	ti := textinput.New()
	ti.CharLimit = 64

	ta := textarea.New()
	ta.Placeholder = "Type your reply..."
	ta.CharLimit = 512
	ta.SetWidth(60)
	ta.SetHeight(2)
	ta.ShowLineNumbers = false

	now := time.Now()
	return model{
		activeTab:        tabKeys,
		store:            store,
		keysList:         makeList(),
		keysInput:        ti,
		keysNextRefresh:  now.Add(60 * time.Second),
		inboxList:        makeList(),
		inboxTextarea:    ta,
		inboxNextRefresh: now.Add(60 * time.Second),
		logPath:          logPath,
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		fetchKeys(m.store),
		fetchMessages(m.store),
		tickEverySecond(),
	}
	if m.logPath != "" {
		cmds = append(cmds, pollLog(m.logPath, 0))
	}
	return tea.Batch(cmds...)
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return secondTickMsg(t) })
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func fetchKeys(store *sqlite.APIKeyStore) tea.Cmd {
	return func() tea.Msg {
		keys, err := store.ListAPIKeys(context.Background())
		if err != nil {
			return keysRefreshErrMsg(err)
		}
		return keysRefreshedMsg(keys)
	}
}

func fetchMessages(store *sqlite.APIKeyStore) tea.Cmd {
	return func() tea.Msg {
		msgs, err := store.ListAllAgentMessages(context.Background())
		if err != nil {
			return inboxRefreshErrMsg(err)
		}
		return inboxRefreshedMsg(msgs)
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

func sendReply(store *sqlite.APIKeyStore, keyName, message string) tea.Cmd {
	return func() tea.Msg {
		if err := store.CreateInboxMessage(context.Background(), keyName, message); err != nil {
			return replyErrMsg(err)
		}
		return replySentMsg{}
	}
}

func pollLog(path string, offset int64) tea.Cmd {
	return func() tea.Msg {
		f, err := os.Open(path)
		if err != nil {
			return logPollMsg{newOffset: offset}
		}
		defer f.Close()

		// Handle log rotation: if the file shrank, restart from the beginning.
		info, err := f.Stat()
		if err != nil {
			return logPollMsg{newOffset: offset}
		}
		if info.Size() < offset {
			offset = 0
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return logPollMsg{newOffset: offset}
		}

		data, err := io.ReadAll(f)
		if err != nil || len(data) == 0 {
			return logPollMsg{newOffset: offset}
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		return logPollMsg{lines: lines, newOffset: offset + int64(len(data))}
	}
}

// keysFingerprint returns a string that changes whenever any key's observable
// state changes (count, active status, usage, quota).
func keysFingerprint(keys []sqlite.APIKeyRecord) string {
	var sb strings.Builder
	for _, k := range keys {
		limit := int64(-1) // sentinel for nil (unlimited)
		if k.DailyLimit != nil {
			limit = *k.DailyLimit
		}
		fmt.Fprintf(&sb, "%d:%v:%d:%d:%d;", k.ID, k.Active, k.UsageCount, k.DailyCount, limit)
	}
	return sb.String()
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
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		m.keysInput.Width = msg.Width - 8
		m.inboxList.SetSize(m.leftWidth(), m.inboxContentHeight())
		m.inboxTextarea.SetWidth(msg.Width - 4)
		return m, nil

	case secondTickMsg:
		t := time.Time(msg)
		cmds := []tea.Cmd{tickEverySecond()}
		if !t.Before(m.keysNextRefresh) {
			m.keysNextRefresh = t.Add(60 * time.Second)
			cmds = append(cmds, fetchKeys(m.store))
		}
		if !t.Before(m.inboxNextRefresh) {
			m.inboxNextRefresh = t.Add(60 * time.Second)
			cmds = append(cmds, fetchMessages(m.store))
		}
		if m.logPath != "" {
			cmds = append(cmds, pollLog(m.logPath, m.logOffset))
		}
		return m, tea.Batch(cmds...)

	// Keys tab messages.
	case keysRefreshedMsg:
		if m.activeTab != tabKeys && keysFingerprint([]sqlite.APIKeyRecord(msg)) != keysFingerprint(m.keysKeys) {
			m.keysChanged = true
		}
		m.keysKeys = []sqlite.APIKeyRecord(msg)
		m.keysLastRefresh = time.Now()
		m.keysNewKeyRaw = ""
		m.keysNewKeyName = ""
		m.keysErr = nil
		idx := m.keysList.Index()
		items := make([]list.Item, len(m.keysKeys))
		for i, k := range m.keysKeys {
			items[i] = keyItem{k}
		}
		m.keysList.SetItems(items)
		if idx < len(items) {
			m.keysList.Select(idx)
		}
		return m, nil

	case keysRefreshErrMsg:
		m.keysErr = error(msg)
		return m, nil

	case keyCreatedMsg:
		m.keysNewKeyName = msg.name
		m.keysNewKeyRaw = msg.raw
		m.keysStatusMsg = fmt.Sprintf("Key %q created — copy the key shown on the right.", msg.name)
		m.keysErr = nil
		return m, fetchKeys(m.store)

	case keyCreateErrMsg:
		m.keysErr = error(msg)
		return m, nil

	case keyRevokedMsg:
		m.keysStatusMsg = "Key revoked."
		m.keysErr = nil
		return m, fetchKeys(m.store)

	case keyRevokeErrMsg:
		m.keysErr = error(msg)
		return m, nil

	case quotaSetMsg:
		m.keysStatusMsg = "Quota updated."
		m.keysErr = nil
		return m, fetchKeys(m.store)

	case quotaSetErrMsg:
		m.keysErr = error(msg)
		return m, nil

	case quotaClearedMsg:
		m.keysStatusMsg = "Quota cleared."
		m.keysErr = nil
		return m, fetchKeys(m.store)

	case quotaClearErrMsg:
		m.keysErr = error(msg)
		return m, nil

	// Inbox tab messages.
	case inboxRefreshedMsg:
		if m.activeTab != tabInbox && len(msg) != len(m.inboxMessages) {
			m.inboxChanged = true
		}
		m.inboxMessages = []sqlite.AgentMessageWithKeyName(msg)
		m.inboxLastRefresh = time.Now()
		m.inboxErr = nil
		idx := m.inboxList.Index()
		items := make([]list.Item, len(m.inboxMessages))
		for i, v := range m.inboxMessages {
			items[i] = msgItem{v}
		}
		m.inboxList.SetItems(items)
		if idx < len(items) {
			m.inboxList.Select(idx)
		}
		return m, nil

	case inboxRefreshErrMsg:
		m.inboxErr = error(msg)
		return m, nil

	case replySentMsg:
		m.inboxReplying = false
		m.inboxTextarea.Reset()
		m.inboxSelected = nil
		m.inboxStatusMsg = "Reply sent."
		m.inboxErr = nil
		m.inboxList.SetSize(m.leftWidth(), m.inboxContentHeight())
		return m, nil

	case replyErrMsg:
		m.inboxErr = error(msg)
		return m, nil

	// Logs tab messages.
	case logPollMsg:
		if len(msg.lines) > 0 {
			if m.activeTab != tabLogs {
				m.logsChanged = true
			}
			m.logLines = append(m.logLines, msg.lines...)
			if len(m.logLines) > maxLogLines {
				m.logLines = m.logLines[len(m.logLines)-maxLogLines:]
			}
		}
		m.logOffset = msg.newOffset
		return m, nil

	case tea.KeyMsg:
		// Global controls active when not inside a text input.
		if !m.isInputActive() {
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "1":
				m.activeTab = tabKeys
				m.keysChanged = false
				return m, nil
			case "2":
				m.activeTab = tabInbox
				m.inboxChanged = false
				return m, nil
			case "3":
				m.activeTab = tabLogs
				m.logsChanged = false
				return m, nil
			case "tab":
				m.activeTab = (m.activeTab + 1) % 3
				switch m.activeTab {
				case tabKeys:
					m.keysChanged = false
				case tabInbox:
					m.inboxChanged = false
				case tabLogs:
					m.logsChanged = false
				}
				return m, nil
			}
		}

		// Route to the active tab's key handler.
		switch m.activeTab {
		case tabKeys:
			return m.updateKeysKey(msg)
		case tabInbox:
			return m.updateInboxKey(msg)
		case tabLogs:
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m, nil
		}
	}

	// Route non-key messages to the correct interactive component.
	switch m.activeTab {
	case tabKeys:
		if m.keysMode == keysBrowse {
			var cmd tea.Cmd
			m.keysList, cmd = m.keysList.Update(msg)
			return m, cmd
		}
		var cmd tea.Cmd
		m.keysInput, cmd = m.keysInput.Update(msg)
		return m, cmd
	case tabInbox:
		if m.inboxReplying {
			var cmd tea.Cmd
			m.inboxTextarea, cmd = m.inboxTextarea.Update(msg)
			return m, cmd
		}
		var cmd tea.Cmd
		m.inboxList, cmd = m.inboxList.Update(msg)
		return m, cmd
	}
	return m, nil
}

// isInputActive reports whether the user is currently typing into a text field,
// which suppresses global tab-switching shortcuts.
func (m model) isInputActive() bool {
	return (m.activeTab == tabKeys && m.keysMode != keysBrowse) ||
		(m.activeTab == tabInbox && m.inboxReplying)
}

// ---------------------------------------------------------------------------
// Keys tab key handlers
// ---------------------------------------------------------------------------

func (m model) updateKeysKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.keysMode {
	case keysNewKeyName, keysSetQuota:
		return m.updateKeysInput(msg)
	case keysConfirmRevoke:
		return m.updateKeysConfirmRevoke(msg)
	default:
		return m.updateKeysBrowse(msg)
	}
}

func (m model) updateKeysBrowse(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "r", "R":
		m.keysNewKeyRaw = ""
		m.keysNewKeyName = ""
		m.keysNextRefresh = time.Now().Add(60 * time.Second)
		return m, fetchKeys(m.store)

	case "n":
		m.keysMode = keysNewKeyName
		m.keysInput.Placeholder = "e.g. my-agent"
		m.keysInput.SetValue("")
		m.keysInput.Focus()
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		return m, textinput.Blink

	case "x":
		item, ok := m.keysList.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		m.keysMode = keysConfirmRevoke
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		return m, nil

	case "s":
		item, ok := m.keysList.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		current := ""
		if item.key.DailyLimit != nil {
			current = strconv.FormatInt(*item.key.DailyLimit, 10)
		}
		m.keysMode = keysSetQuota
		m.keysInput.Placeholder = "requests per day"
		m.keysInput.SetValue(current)
		m.keysInput.Focus()
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		return m, textinput.Blink

	case "c":
		item, ok := m.keysList.SelectedItem().(keyItem)
		if !ok || !item.key.Active {
			return m, nil
		}
		return m, doClearQuota(m.store, item.key.ID)
	}

	var cmd tea.Cmd
	m.keysList, cmd = m.keysList.Update(msg)
	return m, cmd
}

func (m model) updateKeysInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.keysMode = keysBrowse
		m.keysInput.SetValue("")
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		return m, nil
	case "enter":
		val := strings.TrimSpace(m.keysInput.Value())
		if val == "" {
			return m, nil
		}
		currentMode := m.keysMode
		m.keysMode = keysBrowse
		m.keysInput.SetValue("")
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		switch currentMode {
		case keysNewKeyName:
			return m, doCreateKey(m.store, val)
		case keysSetQuota:
			item, ok := m.keysList.SelectedItem().(keyItem)
			if !ok {
				return m, nil
			}
			limit, err := strconv.ParseInt(val, 10, 64)
			if err != nil || limit <= 0 {
				m.keysErr = fmt.Errorf("invalid quota %q: must be a positive integer", val)
				return m, nil
			}
			return m, doSetQuota(m.store, item.key.ID, limit)
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.keysInput, cmd = m.keysInput.Update(msg)
	return m, cmd
}

func (m model) updateKeysConfirmRevoke(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "n", "N":
		m.keysMode = keysBrowse
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		return m, nil
	case "y", "Y":
		item, ok := m.keysList.SelectedItem().(keyItem)
		m.keysMode = keysBrowse
		m.keysList.SetSize(m.leftWidth(), m.keysContentHeight())
		if !ok {
			return m, nil
		}
		return m, doRevokeKey(m.store, item.key.ID)
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Inbox tab key handlers
// ---------------------------------------------------------------------------

func (m model) updateInboxKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.inboxReplying {
		return m.updateInboxReplying(msg)
	}
	return m.updateInboxBrowsing(msg)
}

func (m model) updateInboxBrowsing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		item, ok := m.inboxList.SelectedItem().(msgItem)
		if !ok || len(m.inboxMessages) == 0 {
			return m, nil
		}
		selected := item.msg
		m.inboxSelected = &selected
		m.inboxReplying = true
		m.inboxTextarea.Reset()
		m.inboxTextarea.Focus()
		m.inboxList.SetSize(m.leftWidth(), m.inboxContentHeight())
		return m, textarea.Blink

	case "r":
		m.inboxNextRefresh = time.Now().Add(60 * time.Second)
		return m, fetchMessages(m.store)
	}

	var cmd tea.Cmd
	m.inboxList, cmd = m.inboxList.Update(msg)
	return m, cmd
}

func (m model) updateInboxReplying(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.inboxReplying = false
		m.inboxTextarea.Reset()
		m.inboxSelected = nil
		m.inboxStatusMsg = ""
		m.inboxList.SetSize(m.leftWidth(), m.inboxContentHeight())
		return m, nil
	case "enter":
		text := strings.TrimSpace(m.inboxTextarea.Value())
		if text == "" {
			return m, nil
		}
		return m, sendReply(m.store, m.inboxSelected.KeyName, text)
	}

	var cmd tea.Cmd
	m.inboxTextarea, cmd = m.inboxTextarea.Update(msg)
	return m, cmd
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func (m model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Lines 1-3: centered ASCII art box with YapGuard! branding.
	const boxLabel = "   YapGuard!   "
	boxInnerW := len(boxLabel)
	boxTotalW := boxInnerW + 2 // +2 for │ on each side
	boxLeft := (m.width - boxTotalW) / 2
	if boxLeft < 0 {
		boxLeft = 0
	}
	lPad := strings.Repeat(" ", boxLeft)
	borderSt := lipgloss.NewStyle().Foreground(lipgloss.Color("#5fdfb0"))

	// Line 1: top border.
	b.WriteString(lPad + borderSt.Render("╭"+strings.Repeat("─", boxInnerW)+"╮"))
	b.WriteString("\n")

	// Line 2: brand text + hints right-aligned in remaining space.
	hints := hintStyle.Render("tab: switch  ·  q: quit")
	hintsW := lipgloss.Width(hints)
	afterBox := m.width - boxLeft - boxTotalW
	hintPad := afterBox - hintsW - 1
	if hintPad < 1 {
		hintPad = 1
	}
	b.WriteString(lPad + borderSt.Render("│") + brandStyle.Render(boxLabel) + borderSt.Render("│"))
	b.WriteString(strings.Repeat(" ", hintPad) + hints)
	b.WriteString("\n")

	// Line 3: bottom border.
	b.WriteString(lPad + borderSt.Render("╰"+strings.Repeat("─", boxInnerW)+"╯"))
	b.WriteString("\n")

	// Line 4: tab pills.
	tabChanged := map[tab]bool{
		tabKeys:  m.keysChanged,
		tabInbox: m.inboxChanged,
		tabLogs:  m.logsChanged,
	}
	renderTab := func(label string, t tab) string {
		if m.activeTab == t {
			return activeTabStyle.Render(label)
		}
		if tabChanged[t] {
			return changedTabStyle.Render(label + " ●")
		}
		return inactiveTabStyle.Render(label)
	}
	b.WriteString(renderTab("  Keys  ", tabKeys))
	b.WriteString(renderTab("  Inbox  ", tabInbox))
	b.WriteString(renderTab("  Logs  ", tabLogs))
	b.WriteString("\n")

	// Line 5: hr.
	b.WriteString(hrStyle.Render(strings.Repeat("─", m.width)))
	b.WriteString("\n")

	// Active tab content.
	switch m.activeTab {
	case tabKeys:
		b.WriteString(m.viewKeys())
	case tabInbox:
		b.WriteString(m.viewInbox())
	case tabLogs:
		b.WriteString(m.viewLogs())
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// Keys tab view
// ---------------------------------------------------------------------------

func (m model) viewKeys() string {
	var b strings.Builder

	contentH := m.keysContentHeight()
	leftW := m.leftWidth()
	rightInnerW := m.width - leftW - 3

	leftPane := lipgloss.NewStyle().Width(leftW).Height(contentH).Render(m.keysList.View())
	rightPane := rightPaneStyle.Width(rightInnerW).Height(contentH).Render(m.renderKeysDetail(rightInnerW))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane))

	switch m.keysMode {
	case keysNewKeyName:
		b.WriteString("\n")
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render("New key — enter a name"),
			m.keysInput.View(),
			hintStyle.Render("[enter] create  ·  [esc] cancel"),
		)
		b.WriteString(actionPaneStyle.Width(m.width - 2).Render(inner))

	case keysSetQuota:
		b.WriteString("\n")
		item, _ := m.keysList.SelectedItem().(keyItem)
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render(
				fmt.Sprintf("Daily quota for %s (requests/day)", item.key.Name),
			),
			m.keysInput.View(),
			hintStyle.Render("[enter] save  ·  [esc] cancel"),
		)
		b.WriteString(actionPaneStyle.Width(m.width - 2).Render(inner))

	case keysConfirmRevoke:
		b.WriteString("\n")
		item, _ := m.keysList.SelectedItem().(keyItem)
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ff5555")).
				Render(fmt.Sprintf("Revoke %q?", item.key.Name)),
			hintStyle.Render("This cannot be undone."),
			hintStyle.Render("[y] confirm  ·  [esc / n] cancel"),
		)
		b.WriteString(confirmPaneStyle.Width(m.width - 2).Render(inner))
	}

	// Status bar.
	b.WriteString("\n")
	activeCount := 0
	for _, k := range m.keysKeys {
		if k.Active {
			activeCount++
		}
	}
	refreshStr := "never"
	if !m.keysLastRefresh.IsZero() {
		refreshStr = m.keysLastRefresh.Format("15:04:05")
	}
	countdown := int(time.Until(m.keysNextRefresh).Seconds()) + 1
	if countdown < 0 {
		countdown = 0
	}
	info := fmt.Sprintf("%d active / %d total  ·  refreshed %s  ·  next in %ds  ·  n: new  r: refresh",
		activeCount, len(m.keysKeys), refreshStr, countdown)
	if m.keysErr != nil {
		b.WriteString(errorBarStyle.Width(m.width).Render("error: " + m.keysErr.Error()))
	} else if m.keysStatusMsg != "" {
		b.WriteString(statusBarStyle.Width(m.width).Render(m.keysStatusMsg))
	} else {
		b.WriteString(statusBarStyle.Width(m.width).Render(info))
	}

	return b.String()
}

func (m model) renderKeysDetail(w int) string {
	item, ok := m.keysList.SelectedItem().(keyItem)
	if !ok {
		return emptyDetailStyle.Render("select a key to see details")
	}
	k := item.key

	if m.keysNewKeyRaw != "" && m.keysNewKeyName == k.Name {
		return lipgloss.JoinVertical(lipgloss.Left,
			detailLabelStyle.Render(k.Name+"  — created"),
			"",
			newKeyWarningStyle.Render("API key (shown once — copy now):"),
			"",
			newKeyValueStyle.Width(w).Render(m.keysNewKeyRaw),
			"",
			hintStyle.Render("press [r] or navigate away to dismiss"),
		)
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

// ---------------------------------------------------------------------------
// Inbox tab view
// ---------------------------------------------------------------------------

func (m model) viewInbox() string {
	var b strings.Builder

	contentH := m.inboxContentHeight()
	leftW := m.leftWidth()
	rightInnerW := m.width - leftW - 3

	leftPane := lipgloss.NewStyle().Width(leftW).Height(contentH).Render(m.inboxList.View())
	rightPane := rightPaneStyle.Width(rightInnerW).Height(contentH).Render(m.renderInboxDetail(rightInnerW))
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane))

	if m.inboxReplying && m.inboxSelected != nil {
		b.WriteString("\n")
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render(fmt.Sprintf("Reply to %s", m.inboxSelected.KeyName)),
			m.inboxTextarea.View(),
			hintStyle.Render("[enter] send  ·  [esc] cancel"),
		)
		b.WriteString(replyBorderStyle.Width(m.width - 2).Render(inner))
	}

	// Status bar.
	b.WriteString("\n")
	refreshStr := "never"
	if !m.inboxLastRefresh.IsZero() {
		refreshStr = m.inboxLastRefresh.Format("15:04:05")
	}
	countdown := int(time.Until(m.inboxNextRefresh).Seconds()) + 1
	if countdown < 0 {
		countdown = 0
	}
	info := fmt.Sprintf("%d message(s)  ·  refreshed %s  ·  next in %ds  ·  enter: reply  r: refresh",
		len(m.inboxMessages), refreshStr, countdown)
	if m.inboxErr != nil {
		b.WriteString(errorBarStyle.Width(m.width).Render("error: " + m.inboxErr.Error()))
	} else if m.inboxStatusMsg != "" {
		b.WriteString(statusBarStyle.Width(m.width).Render(m.inboxStatusMsg))
	} else {
		b.WriteString(statusBarStyle.Width(m.width).Render(info))
	}

	return b.String()
}

func (m model) renderInboxDetail(w int) string {
	item, ok := m.inboxList.SelectedItem().(msgItem)
	if !ok {
		return emptyDetailStyle.Render("select a message to read it")
	}
	msg := item.msg
	return lipgloss.JoinVertical(lipgloss.Left,
		detailLabelStyle.Render(msg.KeyName),
		detailMetaStyle.Render(fmt.Sprintf("#%d  ·  %s", msg.ID, msg.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))),
		"",
		detailBodyStyle.Render(wordwrap.String(msg.Message, w)),
	)
}

// ---------------------------------------------------------------------------
// Logs tab view
// ---------------------------------------------------------------------------

func (m model) viewLogs() string {
	var b strings.Builder

	contentH := m.logsContentHeight()

	if m.logPath == "" {
		pad := lipgloss.NewStyle().Width(m.width).Height(contentH)
		b.WriteString(pad.Render(logNoFileStyle.Render("no log file configured — use the -log flag to specify a path")))
		b.WriteString("\n")
		b.WriteString(statusBarStyle.Width(m.width).Render("tip: dashboard -log /app/storage/server.log"))
		return b.String()
	}

	// Show the last contentH lines, padded with blank lines at the top so
	// new entries always appear at the bottom (tail -f style).
	lines := m.logLines
	if len(lines) > contentH {
		lines = lines[len(lines)-contentH:]
	}
	nPad := contentH - len(lines)
	rendered := make([]string, 0, contentH)
	for i := 0; i < nPad; i++ {
		rendered = append(rendered, "")
	}
	for _, l := range lines {
		rendered = append(rendered, logLineStyle.Render(l))
	}
	b.WriteString(strings.Join(rendered, "\n"))
	b.WriteString("\n")
	b.WriteString(statusBarStyle.Width(m.width).Render(fmt.Sprintf("tailing %s  ·  %d line(s) buffered", m.logPath, len(m.logLines))))

	return b.String()
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

// headerLines is the number of terminal rows consumed by the header section
// (box top + box mid + box bottom + tab pills + hr).
const headerLines = 5

func (m model) keysContentHeight() int {
	h := m.height - headerLines - 1 // 1 for status line
	if m.keysMode != keysBrowse {
		h -= 6 // \n + action pane (border×2 + label + input + hint)
	}
	if h < 1 {
		h = 1
	}
	return h
}

func (m model) inboxContentHeight() int {
	h := m.height - headerLines - 1 // 1 for status line
	if m.inboxReplying {
		h -= 7 // reply pane: border top/bottom + title + textarea(2) + hint + blank
	}
	if h < 1 {
		h = 1
	}
	return h
}

func (m model) logsContentHeight() int {
	h := m.height - headerLines - 1 // 1 for status line
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
	logPath := flag.String("log", "", "path to server log file to tail (optional)")
	flag.Parse()

	db, err := sqlite.OpenAndInit(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error opening database:", err)
		os.Exit(1)
	}
	defer db.Close()

	store := sqlite.NewAPIKeyStore(db)

	p := tea.NewProgram(newModel(store, *logPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
