//go:build linux

package l3rewrite

import (
	"context"
	"sync"
	"testing"
	"time"

	nfq "github.com/florianl/go-nfqueue/v2"
	"github.com/sirupsen/logrus"
)

type fakePacketQueue struct {
	accept                    func()
	accepted, altered, closed int
}

func (q *fakePacketQueue) SetVerdict(_ uint32, _ int) error {
	if q.accept != nil {
		q.accept()
	}
	q.accepted++
	return nil
}

func (q *fakePacketQueue) SetVerdictWithOption(_ uint32, _ int, _ ...nfq.VerdictOption) error {
	q.altered++
	return nil
}

func (q *fakePacketQueue) Close() error { q.closed++; return nil }

func TestEnqueueHighBitHash(t *testing.T) {
	tcp := synTCP(8192, false)
	tcp.SrcPort = 40001
	data := buildIPv4TCP(t, tcp, 1)
	if flowHash(data) != 3660109209 {
		t.Fatalf("unexpected fixture hash: %d", flowHash(data))
	}
	id := uint32(1)
	for workers := 2; workers <= 8; workers++ {
		s := &nfqueueServer{nf: &fakePacketQueue{}, chans: make([]chan *nfq.Attribute, workers)}
		for i := range s.chans {
			s.chans[i] = make(chan *nfq.Attribute, 1)
		}
		s.enqueue(nfq.Attribute{PacketID: &id, Payload: &data})
		idx := int(uint64(3660109209) % uint64(workers))
		if len(s.chans[idx]) != 1 {
			t.Fatalf("packet not routed to worker %d", idx)
		}
		s.Close()
	}
}

func TestHandleTruncatedCaptureAcceptsOriginal(t *testing.T) {
	data := buildIPv4TCP(t, synTCP(1024, true), 1)
	id, capLen := uint32(1), uint32(len(data)+100)
	q := &fakePacketQueue{}
	s := &nfqueueServer{nf: q, cfg: Config{IPID: true, TCPTS: true}, log: logrus.New()}
	s.handle(&nfq.Attribute{PacketID: &id, Payload: &data, CapLen: &capLen})
	if q.accepted != 1 || q.altered != 0 {
		t.Fatalf("verdicts: accept=%d altered=%d", q.accepted, q.altered)
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle operation did not finish")
	}
}

func TestCloseWaitsForCallbackAndRejectsLaterPackets(t *testing.T) {
	entered, release, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	q := &fakePacketQueue{accept: func() { close(entered); <-release }}
	ctx, cancel := context.WithCancel(context.Background())
	s := &nfqueueServer{nf: q, cancel: cancel, chans: []chan *nfq.Attribute{make(chan *nfq.Attribute)}}
	id := uint32(1)
	go func() { s.enqueue(nfq.Attribute{PacketID: &id}); close(callbackDone) }()
	waitSignal(t, entered)
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	waitSignal(t, ctx.Done())
	select {
	case <-closed:
		t.Fatal("Close returned while callback was active")
	default:
	}
	unblock()
	waitSignal(t, callbackDone)
	waitSignal(t, closed)
	data := buildIPv4TCP(t, synTCP(8192, false), 1)
	if got := s.enqueue(nfq.Attribute{PacketID: &id, Payload: &data}); got != 1 {
		t.Fatalf("late callback = %d, want stop", got)
	}
	s.Close()
	if q.accepted != 1 || q.closed != 1 {
		t.Fatalf("accept=%d close=%d", q.accepted, q.closed)
	}
}

func TestCloseDrainsWorkersBeforeClosingQueue(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	q := &fakePacketQueue{accept: func() { close(entered); <-release }}
	s := &nfqueueServer{nf: q, chans: []chan *nfq.Attribute{make(chan *nfq.Attribute, 1)}}
	id := uint32(1)
	s.chans[0] <- &nfq.Attribute{PacketID: &id}
	s.wg.Add(1)
	go s.worker(s.chans[0])
	waitSignal(t, entered)
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	unblock()
	waitSignal(t, closed)
	if q.accepted != 1 || q.closed != 1 {
		t.Fatalf("accept=%d close=%d", q.accepted, q.closed)
	}
}
