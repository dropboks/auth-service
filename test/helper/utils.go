package helper

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Register(email string, t *testing.T) *http.Request {
	reqBody := &bytes.Buffer{}
	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", email)
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	assert.NoError(t, err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	formWriter.Close()

	request, err := http.NewRequest(http.MethodPost, "http://localhost:8181/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())

	assert.NoError(t, err)
	return request
}

func RetrieveDataFromEmail(email string, t *testing.T) string {
	var (
		mailhogResp struct {
			Total int `json:"total"`
			Items []struct {
				ID      string `json:"ID"`
				Content struct {
					Headers map[string][]string `json:"Headers"`
					Body    string              `json:"Body"`
				} `json:"Content"`
			} `json:"items"`
		}
		emailFound bool
	)
	mailhogURL := "http://localhost:8025/api/v2/messages"
	var emailItems *struct {
		ID      string `json:"ID"`
		Content struct {
			Headers map[string][]string `json:"Headers"`
			Body    string              `json:"Body"`
		} `json:"Content"`
	}
	for range 10 {
		resp, err := http.Get(mailhogURL)
		assert.NoError(t, err)

		defer resp.Body.Close()

		mailhogResp.Total = 0
		err = json.NewDecoder(resp.Body).Decode(&mailhogResp)
		assert.NoError(t, err)

		for _, item := range mailhogResp.Items {
			toList := item.Content.Headers["To"]
			for _, to := range toList {
				if strings.EqualFold(strings.TrimSpace(to), email) {
					emailItems = &item
					emailFound = true
					break
				}
			}
			if emailFound {
				break
			}
		}
		if emailFound {
			break
		}
		time.Sleep(2 * time.Second)
	}
	assert.True(t, emailFound, "No email received by "+email+" after waiting")
	qpReader := quotedprintable.NewReader(strings.NewReader(emailItems.Content.Body))
	decodedBody, err := io.ReadAll(qpReader)
	assert.NoError(t, err)

	bodyStr := string(decodedBody)
	bodyStr = strings.ReplaceAll(bodyStr, "&amp;", "&")
	re := regexp.MustCompile(`http://localhost:8181/verify-email\?userid=[^&]+&token=[^"']+`)
	link := re.FindString(bodyStr)
	assert.NotEmpty(t, link, "Verification link not found in email")
	return link
}
