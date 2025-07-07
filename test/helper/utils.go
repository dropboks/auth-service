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

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func Login(email string, t *testing.T) *http.Request {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    email,
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8181/login", reqBody)
	assert.NoError(t, err)
	return req
}

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

func RetrieveDataFromEmail(email, regex, types string, t *testing.T) string {
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

	var link string
	re := regexp.MustCompile(regex)

	for range 10 {
		resp, err := http.Get(mailhogURL)
		assert.NoError(t, err)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		mailhogResp.Total = 0
		err = json.NewDecoder(resp.Body).Decode(&mailhogResp)
		resp.Body.Close()
		assert.NoError(t, err)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		emailFound = false
		link = ""

		for _, item := range mailhogResp.Items {
			toList := item.Content.Headers["To"]
			for _, to := range toList {
				if strings.EqualFold(strings.TrimSpace(to), email) {
					// decode body
					qpReader := quotedprintable.NewReader(strings.NewReader(item.Content.Body))
					decodedBody, err := io.ReadAll(qpReader)
					if err != nil {
						continue
					}
					bodyStr := string(decodedBody)
					bodyStr = strings.ReplaceAll(bodyStr, "&amp;", "&")
					if types == "otp" {
						matches := re.FindStringSubmatch(bodyStr)
						if len(matches) > 1 {
							link = matches[1]
							emailFound = true
							break
						} else if len(matches) == 1 {
							link = matches[0]
							emailFound = true
							break
						}
					} else {
						found := re.FindString(bodyStr)
						if found != "" {
							link = found
							emailFound = true
							break
						}
					}
				}
			}
			if emailFound {
				break
			}
		}
		if emailFound && link != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}

	assert.True(t, emailFound && link != "", "No matching email content found for "+email+" after waiting")
	return link
}
