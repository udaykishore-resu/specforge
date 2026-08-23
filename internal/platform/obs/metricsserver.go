package obs

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// ServeMetrics runs a metrics endpoint on its own listener until ctx is done.
//
// Two reasons this is separate from the application's HTTP server rather than
// another route on it:
//
//   - The worker has no HTTP server at all. Without this it exposes nothing, so
//     every metric it owns — the outbox depth, the age of the oldest
//     unpublished event, whether the audit chain last verified — is invisible.
//     A dashboard panel that is always empty and an alert that can never fire
//     are worse than none, because both read as "nothing is wrong".
//   - A metrics port is an operational surface, not a public one. Keeping it on
//     a separate address means it can be bound where only the scraper reaches
//     it, without threading exceptions through the request middleware.
//
// The caller supplies onScrape for anything that must be sampled at scrape time
// rather than continuously, such as connection-pool gauges. It may be nil.
func ServeMetrics(ctx context.Context, addr string, logger *slog.Logger, onScrape func()) error {
	if addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if onScrape != nil {
			onScrape()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(Gather()))
	})
	// A liveness probe on the same listener, so a process with no other HTTP
	// surface can still be probed.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
