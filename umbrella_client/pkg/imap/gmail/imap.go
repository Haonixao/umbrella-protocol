package gmail

import (
	"bytes"
	"errors"
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

func (g *GmailImap) GetUmbrellaMeta() (string, error) {
	c, err := g.setupImapClient()
	if err != nil {
		return "", err
	}
	defer c.Logout()

	crit := imap.NewSearchCriteria()
	crit.Header.Add("Subject", "[Umbrella meta]")
	ids, err := c.Search(crit)
	if err != nil {
		return "", fmt.Errorf("search error: %w", err)
	}

	if len(ids) == 0 {
		return "", errors.New("no draft found with Subject \"[Umbrella meta]\"")
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(ids[0])

	messages := make(chan *imap.Message, 1)
	fetchDone := make(chan error, 1)
	go func() {
		fetchDone <- c.Fetch(seqset, []imap.FetchItem{
			imap.FetchEnvelope,
			imap.FetchRFC822Text,
			imap.FetchUid,
			imap.FetchFlags,
		}, messages)
	}()

	var bodyContent string
	for msg := range messages {
		r := msg.GetBody(&imap.BodySectionName{})
		if r == nil {
			for _, literal := range msg.Body {
				if literal == nil {
					continue
				}
				bodyBytes, err := io.ReadAll(literal)
				if err != nil {
					return "", fmt.Errorf("failed to read body: %w", err)
				}
				bodyContent = string(bodyBytes)
				break
			}
			if bodyContent == "" {
				log.Printf("[ERR] Message body is nil for UID %v", msg.Uid)
			}
			continue
		}

		bodyBytes, err := io.ReadAll(r)
		if err != nil {
			return "", fmt.Errorf("failed to read body: %w", err)
		}
		bodyContent = string(bodyBytes)
	}

	if fetchErr := <-fetchDone; fetchErr != nil {
		return "", fmt.Errorf("fetch error: %w", fetchErr)
	}

	return bodyContent, nil
}

func (g *GmailImap) PostUmbrellaRequest(request string) error {
	// Open a temporary IMAP client and ensure it is logged out afterwards.
	c, err := g.setupImapClient()
	if err != nil {
		return err
	}
	defer c.Logout()

	// Build a minimal RFC822 message.
	msg := "Subject: [Umbrella request]\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"\r\n" + request + "\r\n"

	// Append it to the Drafts folder.
	return c.Append("[Gmail]/Drafts", []string{imap.DraftFlag}, time.Now(), bytes.NewReader([]byte(msg)))
}

func (g *GmailImap) GetUmbrellaResponse(bodyStr string) (bool, error) {
	c, err := g.setupImapClient()
	if err != nil {
		return false, err
	}
	defer c.Logout()

	for attempt := range 6 {
		c.Noop()

		crit := imap.NewSearchCriteria()
		crit.Header.Add("Subject", "[Umbrella response]")
		ids, err := c.Search(crit)
		if err != nil {
			return false, fmt.Errorf("search error: %w", err)
		}

		if len(ids) > 0 {
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

			var deleteIDs []uint32
			var found bool
			for msg := range messages {
				var bodyContent string

				r := msg.GetBody(&imap.BodySectionName{})
				if r == nil {
					for _, literal := range msg.Body {
						if literal == nil {
							continue
						}
						bodyBytes, err := io.ReadAll(literal)
						if err != nil {
							return false, fmt.Errorf("failed to read body: %w", err)
						}
						bodyContent = string(bodyBytes)
						break
					}
				} else {
					bodyBytes, err := io.ReadAll(r)
					if err != nil {
						return false, fmt.Errorf("failed to read body: %w", err)
					}
					bodyContent = string(bodyBytes)
				}

				if bodyContent == "" {
					log.Printf("[ERR] Message body is nil for UID %v", msg.Uid)
					continue
				}

				if bodyContent == bodyStr || strings.Contains(bodyContent, bodyStr) {
					found = true
					deleteIDs = append(deleteIDs, msg.Uid)
				}
			}

			if fetchErr := <-fetchDone; fetchErr != nil {
				return false, fmt.Errorf("fetch error: %w", fetchErr)
			}

			if len(deleteIDs) > 0 {
				delSeqSet := new(imap.SeqSet)
				delSeqSet.AddNum(deleteIDs...)
				if err := c.UidStore(delSeqSet, imap.AddFlags, []any{imap.DeletedFlag}, nil); err != nil {
					return true, fmt.Errorf("store error: %w", err)
				}
				if err := c.Expunge(nil); err != nil {
					return true, fmt.Errorf("expunge error: %w", err)
				}
			}

			if found {
				return true, nil
			}
		}

		if attempt < 5 {
			time.Sleep(5 * time.Second)
		}
	}

	return false, nil
}

// setupImapClient creates a temporary IMAP client, logs in, selects the Drafts folder and returns the client.
// The caller is responsible for closing the client when done.
func (g *GmailImap) setupImapClient() (*imapclient.Client, error) {
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
