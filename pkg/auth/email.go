package auth

import (
	"encoding/base64"
	"net/http"
	"net/smtp"
	"os"
	"strings"
)

func SendEmail(addr, subject string, file []byte, r *http.Request) error {
	service := os.Getenv("email")
	password := os.Getenv("password")
	host := os.Getenv("email_host")

	// SMTP authentication
	auth := smtp.PlainAuth("", service, password, host)
	var msg []byte

	// Spliting the subject to send file or send OTP
	sub := strings.Split(subject, " ")

	if sub[0] == "Encrypted" {
		// Get the filename
		files := strings.Split(subject, ":")
		fileName := files[1] + ".txt"
		// MIME headers
		boundary := "my"
		subjectHeader := "Subject: " + subject + "\r\n"
		mime := "MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n"

		// Message body (before the attachment)
		body := "--" + boundary + "\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"Content-Transfer-Encoding: 7bit\r\n\r\n" +
			"Please find the attached file.\r\n\r\n"

		// Encoding the file as base64
		fileContent := base64.StdEncoding.EncodeToString(file)

		// Attachment header
		attachment := "--" + boundary + "\r\n" +
			"Content-Type: text/plain; name=\"" + fileName + "\"\r\n" +
			"Content-Transfer-Encoding: base64\r\n" +
			"Content-Disposition: attachment; filename=\"" + fileName + "\"\r\n" +
			fileContent + "\r\n--" + boundary + "--"

		// Full message
		msg = []byte(subjectHeader + mime + body + attachment)

	} else if sub[0] == "OTP" {
		// msg = []byte("To: "+ addr +"\r\n" +
		// 		"subject: " + subject + "\r\n" +
		// 		"\r\n" + string(file) +" ")
	}

	err := smtp.SendMail(host+":587", auth, service, []string{addr}, msg)
	if err != nil {
		return err
	}

	return nil
}
