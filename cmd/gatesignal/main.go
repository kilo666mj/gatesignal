package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kilo666mj/gatesignal/internal/abuse"
	"github.com/kilo666mj/gatesignal/internal/accesslog"
	"github.com/kilo666mj/gatesignal/internal/analytics"
	"github.com/kilo666mj/gatesignal/internal/config"
	"github.com/kilo666mj/gatesignal/internal/ingest"
	"github.com/kilo666mj/gatesignal/internal/metrics"
	"github.com/kilo666mj/gatesignal/internal/publisher"
	"github.com/kilo666mj/gatesignal/internal/store"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/gatesignal/config.json", "path to configuration")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if err := run(*configPath); err != nil {
		log.Fatal(err)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	telemetry := metrics.New()
	state := store.New(cfg.Redis.Address, cfg.Redis.Password, cfg.Redis.DB, cfg.Redis.Namespace)
	defer state.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = state.Ping(pingCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to Redis: %w", err)
	}
	var ownership publisher.Ownership
	if cfg.Signals.Mode == "publish" || cfg.Analytics.Mode == "publish" {
		lease, err := publisher.NewLease(state, telemetry, time.Duration(cfg.Publisher.LeaseTTLSeconds)*time.Second, time.Duration(cfg.Publisher.RenewIntervalSeconds)*time.Second)
		if err != nil {
			return err
		}
		leaseCtx, stopLease := context.WithCancel(ctx)
		lease.Start(leaseCtx)
		defer func() {
			stopLease()
			lease.Wait()
		}()
		ownership = lease
	}
	detector, err := abuse.New(cfg.Signals, state, telemetry, ownership)
	if err != nil {
		return err
	}
	webAnalytics, err := analytics.New(cfg.Analytics, state, telemetry, cfg.Publisher.PipelineID, ownership)
	if err != nil {
		return err
	}
	detector.Start(ctx)
	webAnalytics.Start(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", telemetry.Health)
	mux.HandleFunc("GET /readyz", telemetry.Health)
	mux.HandleFunc("GET /metrics", telemetry.Prometheus)
	server := &http.Server{Addr: cfg.HTTP.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("health and metrics listening on %s", cfg.HTTP.Listen)
		serverErrors <- server.ListenAndServe()
	}()
	streams, err := ingest.Start(ctx, cfg.Inputs, telemetry, func(line string) {
		event, ok := accesslog.Parse(line)
		if !ok {
			telemetry.LinesUnmatched.Add(1)
			return
		}
		telemetry.LinesParsed.Add(1)
		telemetry.LastObservationUnix.Store(event.ObservedAt.Unix())
		detector.Process(ctx, event)
		webAnalytics.Process(event)
	})
	if err != nil {
		return err
	}
	defer streams.Stop()
	telemetry.Ready.Store(true)
	log.Printf("GateSignal ready signals=%s analytics=%s inputs=%d", cfg.Signals.Mode, cfg.Analytics.Mode, len(cfg.Inputs))
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server: %w", err)
		}
	}
	telemetry.ShuttingDown.Store(true)
	telemetry.Ready.Store(false)
	streams.Stop()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}
	streams.Wait()
	return nil
}

func init() { log.SetOutput(os.Stderr) }
