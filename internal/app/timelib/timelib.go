package timelib

import "time"

func GetTimeOfDay(t time.Time) time.Time {
	return time.Date(0, 0, 0, t.Hour(), t.Minute(), 0, 0, time.Local)
}
