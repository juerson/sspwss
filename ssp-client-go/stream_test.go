package main

// streamState（逻辑流接收队列）语义测试：FIFO、不丢帧、关闭后排空残余。

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestStreamQueueFIFOAndNoDrop(t *testing.T) {
	ss := newStreamState()
	const n = 1000
	// 远超旧实现的 32 帧缓冲：验证 unbounded 不丢帧
	for i := 0; i < n; i++ {
		ss.push([]byte{byte(i % 256)})
	}
	for i := 0; i < n; i++ {
		d, ok := ss.tryPop()
		if !ok {
			t.Fatalf("frame %d dropped (unbounded queue must not drop)", i)
		}
		if d[0] != byte(i%256) {
			t.Fatalf("out of order at %d", i)
		}
	}
	if _, ok := ss.tryPop(); ok {
		t.Fatal("queue should be empty")
	}
}

func TestStreamQueueDrainsAfterClose(t *testing.T) {
	// RS mpsc 语义：关闭后已入队数据仍可消费，排空才 EOF
	ss := newStreamState()
	for i := 0; i < 5; i++ {
		ss.push([]byte{byte(i)})
	}
	ss.closeStream()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		d, ok := ss.pop(ctx)
		if !ok {
			t.Fatalf("queued frame %d lost after close", i)
		}
		if d[0] != byte(i) {
			t.Fatalf("out of order after close at %d", i)
		}
	}
	if _, ok := ss.pop(ctx); ok {
		t.Fatal("should EOF after drain")
	}
}

func TestStreamQueuePopUnblocksOnClose(t *testing.T) {
	ss := newStreamState()
	done := make(chan struct{})
	go func() {
		ctx := context.Background()
		_, ok := ss.pop(ctx) // 阻塞在空队列
		if ok {
			t.Error("expected false after close")
		}
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	ss.closeStream()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pop did not unblock on close")
	}
}

func TestStreamQueueConcurrentPushPop(t *testing.T) {
	// 并发压入/消费：总数一致、无丢失
	ss := newStreamState()
	const producers, perProducer = 4, 500

	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				ss.push([]byte{byte(p)})
			}
		}(p)
	}

	total := 0
	deadline := time.After(5 * time.Second)
	for total < producers*perProducer {
		select {
		case <-deadline:
			t.Fatalf("timeout: consumed %d/%d", total, producers*perProducer)
		default:
		}
		if _, ok := ss.tryPop(); ok {
			total++
		} else {
			time.Sleep(time.Millisecond)
		}
	}
	wg.Wait()
	if total != producers*perProducer {
		t.Fatalf("lost frames: got %d want %d", total, producers*perProducer)
	}
}
