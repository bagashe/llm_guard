package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/joho/godotenv"
	"github.com/muesli/reflow/wordwrap"

	"llm_guard/internal/storage/sqlite"
)

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#5fdfb0")).
			PaddingBottom(1)

	// Right detail pane: left border acts as the vertical divider.
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

	detailBodyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#cccccc"))

	emptyDetailStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#444444"))

	replyBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#5fdfb0")).
				Padding(0, 1)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444444"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff5555"))
)

// ---------------------------------------------------------------------------
// List item — shows agent name + timestamp; message lives in the detail pane.
// ---------------------------------------------------------------------------

type msgItem struct {
	msg sqlite.AgentMessageWithKeyName
}

func (i msgItem) Title() string {
	return i.msg.KeyName
}

func (i msgItem) Description() string {
	return fmt.Sprintf("#%d · %s", i.msg.ID, i.msg.CreatedAt.UTC().Format("2006-01-02 15:04"))
}

func (i msgItem) FilterValue() string {
	return i.msg.KeyName
}

// ---------------------------------------------------------------------------
// tea.Msg types
// ---------------------------------------------------------------------------

type secondTickMsg time.Time
type refreshedMsg []sqlite.AgentMessageWithKeyName
type refreshErrMsg error
type replySentMsg struct{}
type replyErrMsg error

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

type model struct {
	list        list.Model
	messages    []sqlite.AgentMessageWithKeyName
	replying    bool
	selected    *sqlite.AgentMessageWithKeyName // reply target
	textarea    textarea.Model
	store       *sqlite.APIKeyStore
	statusMsg   string
	lastRefresh time.Time
	nextRefresh time.Time
	width       int
	height      int
	err         error
}

func newModel(store *sqlite.APIKeyStore) model {
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true
	l := list.New(nil, delegate, 0, 0)
	l.Title = ""
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	ta := textarea.New()
	ta.Placeholder = "Type your reply..."
	ta.CharLimit = 512
	ta.SetWidth(60)
	ta.SetHeight(2)
	ta.ShowLineNumbers = false

	return model{
		list:        l,
		textarea:    ta,
		store:       store,
		nextRefresh: time.Now().Add(60 * time.Second),
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func (m model) Init() tea.Cmd {
	return tea.Batch(fetchMessages(m.store), tickEverySecond())
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return secondTickMsg(t) })
}

func fetchMessages(store *sqlite.APIKeyStore) tea.Cmd {
	return func() tea.Msg {
		msgs, err := store.ListAllAgentMessages(context.Background())
		if err != nil {
			return refreshErrMsg(err)
		}
		return refreshedMsg(msgs)
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

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		m.textarea.SetWidth(msg.Width - 4)
		return m, nil

	case secondTickMsg:
		cmds := []tea.Cmd{tickEverySecond()}
		if !time.Time(msg).Before(m.nextRefresh) {
			m.nextRefresh = time.Time(msg).Add(60 * time.Second)
			cmds = append(cmds, fetchMessages(m.store))
		}
		return m, tea.Batch(cmds...)

	case refreshedMsg:
		m.messages = []sqlite.AgentMessageWithKeyName(msg)
		m.lastRefresh = time.Now()
		m.err = nil
		idx := m.list.Index()
		items := make([]list.Item, len(m.messages))
		for i, v := range m.messages {
			items[i] = msgItem{v}
		}
		m.list.SetItems(items)
		if idx < len(items) {
			m.list.Select(idx)
		}
		return m, nil

	case refreshErrMsg:
		m.err = error(msg)
		return m, nil

	case replySentMsg:
		m.replying = false
		m.textarea.Reset()
		m.selected = nil
		m.statusMsg = "Reply sent."
		m.err = nil
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, nil

	case replyErrMsg:
		m.err = error(msg)
		return m, nil

	case tea.KeyMsg:
		if m.replying {
			return m.updateReplying(msg)
		}
		return m.updateBrowsing(msg)
	}

	if m.replying {
		var cmd tea.Cmd
		m.textarea, cmd = m.textarea.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateBrowsing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "enter":
		item, ok := m.list.SelectedItem().(msgItem)
		if !ok || len(m.messages) == 0 {
			return m, nil
		}
		selected := item.msg
		m.selected = &selected
		m.replying = true
		m.textarea.Reset()
		m.textarea.Focus()
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, textarea.Blink

	case "r":
		m.nextRefresh = time.Now().Add(60 * time.Second)
		return m, fetchMessages(m.store)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) updateReplying(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case "esc":
		m.replying = false
		m.textarea.Reset()
		m.selected = nil
		m.statusMsg = ""
		m.list.SetSize(m.leftWidth(), m.contentHeight())
		return m, nil

	case "enter":
		text := strings.TrimSpace(m.textarea.Value())
		if text == "" {
			return m, nil
		}
		return m, sendReply(m.store, m.selected.KeyName, text)
	}

	var cmd tea.Cmd
	m.textarea, cmd = m.textarea.Update(msg)
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

	// Header
	refreshStr := "never"
	if !m.lastRefresh.IsZero() {
		refreshStr = m.lastRefresh.Format("15:04:05")
	}
	countdown := int(time.Until(m.nextRefresh).Seconds()) + 1
	if countdown < 0 {
		countdown = 0
	}
	header := fmt.Sprintf("INBOX  ·  %d message(s)  ·  refreshed %s  ·  next in %ds  ·  [r] refresh  [q] quit",
		len(m.messages), refreshStr, countdown)
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")

	// Split pane: list (left) | detail (right)
	//   right pane overhead = 1 (border) + 1 (pad-left) + 1 (pad-right) = 3
	contentH := m.contentHeight()
	leftW := m.leftWidth()
	rightInnerW := m.width - leftW - 3

	leftPane := lipgloss.NewStyle().Width(leftW).Height(contentH).Render(m.list.View())
	rightPane := rightPaneStyle.Width(rightInnerW).Height(contentH).Render(m.renderDetail(rightInnerW, contentH))

	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane))

	// Reply pane (bottom, full-width)
	if m.replying && m.selected != nil {
		b.WriteString("\n")
		title := fmt.Sprintf("Reply to %s", m.selected.KeyName)
		inner := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Bold(true).Render(title),
			m.textarea.View(),
			hintStyle.Render("[enter] send  ·  [esc] cancel"),
		)
		b.WriteString(replyBorderStyle.Width(m.width - 2).Render(inner))
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

// renderDetail renders the right-hand message detail pane.
func (m model) renderDetail(w, _ int) string {
	item, ok := m.list.SelectedItem().(msgItem)
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
// Layout helpers
// ---------------------------------------------------------------------------

// leftWidth returns the width of the list pane (~38% of terminal).
func (m model) leftWidth() int {
	w := m.width * 38 / 100
	if w < 28 {
		w = 28
	}
	return w
}

// contentHeight returns the rows available for the list + detail split.
func (m model) contentHeight() int {
	h := m.height
	h -= 2 // header + its padding
	h -= 1 // status line
	if m.replying {
		h -= 7 // reply pane: border top/bottom + title + textarea(2) + hint + blank
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
