// Package ingest follows access-log files produced by a local log router.
package ingest

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/nxadm/tail"

	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/metrics"
)

type Group struct {
	tails []*tail.Tail
	wg    sync.WaitGroup
}

func Start(ctx context.Context, inputs []config.Input, telemetry *metrics.Metrics, process func(string)) (*Group, error) {
	group := &Group{}
	for _, input := range inputs {
		whence := io.SeekEnd
		if input.StartPosition == "beginning" {
			whence = io.SeekStart
		}
		stream, err := tail.TailFile(input.Path, tail.Config{
			Follow: true, ReOpen: true, MustExist: true, CompleteLines: true,
			Location: &tail.SeekInfo{Offset: 0, Whence: whence},
		})
		if err != nil {
			group.Stop()
			return nil, fmt.Errorf("tail %s: %w", input.Path, err)
		}
		group.tails = append(group.tails, stream)
		group.wg.Add(1)
		go func(path string, stream *tail.Tail) {
			defer group.wg.Done()
			for {
				select {
				case <-ctx.Done():
					_ = stream.Stop()
					return
				case line, ok := <-stream.Lines:
					if !ok {
						telemetry.TailRestarts.Add(1)
						log.Printf("input stopped path=%s", path)
						return
					}
					if line.Err != nil {
						log.Printf("input error path=%s err=%v", path, line.Err)
						continue
					}
					telemetry.LinesRead.Add(1)
					process(line.Text)
				}
			}
		}(input.Path, stream)
	}
	return group, nil
}

func (g *Group) Stop() {
	if g == nil {
		return
	}
	for _, stream := range g.tails {
		_ = stream.Stop()
	}
}

func (g *Group) Wait() {
	if g != nil {
		g.wg.Wait()
	}
}
