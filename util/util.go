package util

import (
	"fmt"
	"time"
)

func ParseSSHTimespec(value string) (time.Time, error) {
	switch len(value) {
	case 8: // YYYYMMDD (using local timezone)
		return time.ParseInLocation("20060102", value, time.Local)
	case 9: // YYYYMMDDZ (using UTC)
		return time.Parse("20060102Z", value)
	case 12: // YYYYMMDDHHMM (using local timezone)
		return time.ParseInLocation("200601021504", value, time.Local)
	case 13: // YYYYMMDDHHMMZ (using UTC)
		return time.Parse("200601021504Z", value)
	case 15: // YYYYMMDDHHMMSS (using local timezone)
		return time.ParseInLocation("20060102150405", value, time.Local)
	case 16: // YYYYMMDDHHMMSSZ (using UTC)
		return time.Parse("20060102150405Z", value)
	default:
		return time.Time{}, fmt.Errorf("invalid timespec: %s", value)
	}
}
