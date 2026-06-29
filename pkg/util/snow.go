package util

import (
	"sync"
	"time"
)

type Snowflake struct {
	mu        sync.Mutex
	lastStamp int64
	workerId  int64
	sequence  int64
}

const (
	workerIdBits = 10
	sequenceBits = 12
	maxWorkerId  = -1 ^ (-1 << workerIdBits)
	sequenceMask = -1 ^ (-1 << sequenceBits)
)

func NewSnowflake(workerId int64) *Snowflake {
	if workerId < 0 || workerId > maxWorkerId {
		panic("workerId out of range")
	}
	return &Snowflake{workerId: workerId}
}

func (s *Snowflake) NextID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	if now == s.lastStamp {
		s.sequence = (s.sequence + 1) & sequenceMask
		if s.sequence == 0 {
			for now <= s.lastStamp {
				now = time.Now().UnixMilli()
			}
		}
	} else {
		s.sequence = 0
	}
	s.lastStamp = now

	return (now << (workerIdBits + sequenceBits)) |
		(s.workerId << sequenceBits) |
		s.sequence
}
