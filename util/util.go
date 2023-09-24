package util

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func ShowNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		err := exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	case "linux":
		err := exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	}
}

func ParseTimePattern(patt string) (time.Time, time.Time, error) {
	if strings.Contains(patt, ":") {
		parts := strings.Split(patt, ":")
		if len(parts) != 2 {
			return time.Time{}, time.Time{}, errors.New("invalid time pattern, must contain 0 or 1 ':'")
		}
		duration1, err := time.ParseDuration(parts[0])
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		duration2, err := time.ParseDuration(parts[1])
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		return time.Now().Add(duration1), time.Now().Add(duration2), nil
	} else {
		duration, err := time.ParseDuration(patt)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse duration: %w", err)
		}
		if duration < 0 {
			return time.Now().Add(duration), time.Now(), nil
		} else {
			return time.Now(), time.Now().Add(duration), nil

		}
	}
}

func RenderTime(seconds uint64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 60*60 {
		return fmt.Sprintf("%.1fm", float64(seconds)/60)
	} else if seconds < 24*60*60 {
		return fmt.Sprintf("%.1fh", float64(seconds)/60/60)
	} else {
		return fmt.Sprintf("%.1fd", float64(seconds)/60/60/24)
	}
}
