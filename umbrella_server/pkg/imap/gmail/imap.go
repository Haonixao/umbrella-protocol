package gmail

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	imap "github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
)

// GmailImap stores credentials for a Gmail IMAP account.
// It is a lightweight wrapper – actual IMAP operations are performed
// by the go‑imap client library. The methods below are placeholders
// that will be fleshed out later.
type GmailImap struct {
	Login    string
	Password string
}

// SetUmbrellaMeta stores meta‑information for the umbrella protocol.
// It deletes any existing draft with Subject "[Umbrella meta]" and creates a new one
// containing the provided meta string in the message body.
func (g *GmailImap) SetUmbrellaMeta(meta string) error {
	// Open a temporary IMAP client and ensure it is logged out afterwards.
	c, err := g.SetupImapClient()
	if err != nil {
		return err
	}
	defer c.Logout()

	// ---------------------------------------------------------------------
	// 1. Find and delete existing drafts with Subject "[Umbrella meta]".
	// ---------------------------------------------------------------------
	crit := imap.NewSearchCriteria()
	crit.Header.Add("Subject", "[Umbrella meta]")
	ids, err := c.Search(crit)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		seqset := new(imap.SeqSet)
		seqset.AddNum(ids...)
		// Mark as \Deleted
		if err := c.Store(seqset, imap.AddFlags, []any{imap.DeletedFlag}, nil); err != nil {
			return err
		}
		// Permanently remove from the mailbox.
		if err := c.Expunge(nil); err != nil {
			return err
		}
	}

	// ---------------------------------------------------------------------
	// 2. Append a new draft with the meta data.
	// ---------------------------------------------------------------------
	// Build a minimal RFC822 message.
	msg := "Subject: [Umbrella meta]\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" + meta + "\r\n"
	// Append to the Drafts folder, setting the \Draft flag.
	if err := c.Append("[Gmail]/Drafts", []string{imap.DraftFlag}, time.Now(), bytes.NewReader([]byte(msg))); err != nil {
		return err
	}
	return nil
}

// GetUmbrellaRequests finds all drafts with Subject "[Umbrella request]",
// extracts their body text, deletes them, and returns the collected bodies.
func (g *GmailImap) GetUmbrellaRequests(c *imapclient.Client) ([]string, error) {
	crit := imap.NewSearchCriteria()
	crit.Header.Add("Subject", "[Umbrella request]")
	ids, err := c.Search(crit)
	if err != nil {
		return nil, fmt.Errorf("search error: %w", err)
	}

	var responses []string
	if len(ids) == 0 {
		return responses, nil
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(ids...)

	messages := make(chan *imap.Message, len(ids))
	fetchDone := make(chan error, 1)

	go func() {
		fetchDone <- c.Fetch(seqset, []imap.FetchItem{
			imap.FetchEnvelope,
			imap.FetchRFC822Text,
			imap.FetchUid,
			imap.FetchFlags,
		}, messages)
	}()

	for msg := range messages {
		// GetBody возвращает io.Reader для запрошенной секции.
		// FetchRFC822Text кладёт тело в секцию &BodySectionName{} (пустую).
		r := msg.GetBody(&imap.BodySectionName{})
		if r == nil {
			// Fallback: перебираем все секции в msg.Body
			var found bool
			for _, literal := range msg.Body {
				if literal == nil {
					continue
				}
				var buf strings.Builder
				if _, err := io.Copy(&buf, literal); err != nil {
					log.Printf("[ERR] Failed to copy body for UID %v: %v", msg.Uid, err)
					continue
				}
				responses = append(responses, buf.String())
				found = true
				break
			}
			if !found {
				log.Printf("[ERR] Message body is nil for UID %v", msg.Uid)
			}
			continue
		}

		var buf strings.Builder
		if _, err := io.Copy(&buf, r); err != nil {
			log.Printf("[ERR] Failed to copy body for UID %v: %v", msg.Uid, err)
			continue
		}
		responses = append(responses, buf.String())
	}

	if fetchErr := <-fetchDone; fetchErr != nil {
		return nil, fmt.Errorf("fetch error: %w", fetchErr)
	}

	if err := c.Store(seqset, imap.AddFlags, []any{imap.DeletedFlag}, nil); err != nil {
		return nil, fmt.Errorf("store error: %w", err)
	}

	if err := c.Expunge(nil); err != nil {
		return nil, fmt.Errorf("expunge error: %w", err)
	}

	return responses, nil
}

// PostUmbrellaResponse appends a new Draft to the Drafts folder containing
// the umbrella response as its body and Subject "[Umbrella response]" and
// returns an error if it cannot be appended.
func (g *GmailImap) PostUmbrellaResponse(c *imapclient.Client, response string) error {
	// Build a minimal RFC822 message.
	msg := "Subject: [Umbrella response]\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" + response + "\r\n"

	// Append it to the Drafts folder.
	return c.Append("[Gmail]/Drafts", []string{imap.DraftFlag}, time.Now(), bytes.NewReader([]byte(msg)))
}

// SetupImapClient creates a temporary IMAP client, logs in, selects the Drafts folder and returns the client.
// The caller is responsible for closing the client when done.
func (g *GmailImap) SetupImapClient() (*imapclient.Client, error) {
	// Connect to Gmail's IMAP server with TLS.
	c, err := imapclient.DialTLS("imap.gmail.com:993", nil)
	if err != nil {
		return nil, err
	}
	// Authenticate using the app‑password credentials.
	if err := c.Login(g.Login, g.Password); err != nil {
		c.Logout()
		return nil, err
	}
	// Pre‑select the Drafts folder so subsequent operations work there by default.
	if _, err := c.Select("[Gmail]/Drafts", false); err != nil {
		c.Logout()
		return nil, err
	}
	return c, nil
}
