package main

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
)

var (
	Name        = "analyzejoblog"
	serviceName = semconv.ServiceNameKey.String(Name)
	tracer      trace.Tracer
	fetchlogURL string
)

func init() {
	tracer = otel.Tracer(Name)
	var ok bool
	fetchlogURL, ok = os.LookupEnv("FETCHLOG_URL")
	if !ok {
		fetchlogURL = "http://localhost:8081"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	// get args
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s JOBID", os.Args[0])
	}
	jobid := os.Args[1]

	// find token
	tok, err := loadSciToken()
	if err != nil {
		log.Fatal(err)
	}

	// init tracing
	res, err := resource.New(ctx, resource.WithAttributes(serviceName))
	if err != nil {
		log.Fatal(err)
	}
	shutdownTracerProvider, err := initTracerProvider(ctx, res)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := shutdownTracerProvider(ctx); err != nil {
			log.Fatalf("failed to shutdown TracerProvider: %s", err)
		}
	}()
	// start tracing
	if tp, ok := os.LookupEnv("TRACEPARENT"); ok {
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier{"traceparent": tp})
	}
	ctx, span := tracer.Start(
		ctx,
		Name,
		trace.WithAttributes(
			attribute.String("jobid", jobid),
		))
	defer span.End()
	log.Printf("trace id: %s", span.SpanContext().TraceID().String())

	for _, filename := range []string{"stdout", "stderr"} {
		if err := analyzeFile(ctx, tok, jobid, filename); err != nil {
			log.Printf("failed to analyze file: %s", err)
			span.SetStatus(codes.Error, err.Error())
		}
	}
}

func analyzeFile(ctx context.Context, token, jobid, fileName string) error {
	ctx, span := tracer.Start(ctx, "analyzeFile")
	defer span.End()
	span.SetAttributes(attribute.String("filename", fileName))
	fmt.Printf("\n >>> Analyzing %s/%s\n", jobid, fileName)
	if r, err := getFile(ctx, token, jobid, fileName); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	} else {
		n, err := io.Copy(io.Discard, r)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		fmt.Printf("size: %db\n", n)
	}
	return nil
}

func getFile(ctx context.Context, token, jobid, fileName string) (io.ReadCloser, error) {
	ctx, span := tracer.Start(ctx, "getFile")
	defer span.End()

	var u string
	if fileName == "stderr" || fileName == "stdout" {
		u = fetchlogURL + "/job/" + jobid + "/" + fileName
	} else {
		u = fetchlogURL + "/job/" + jobid + "/file/" + fileName
	}
	log.Printf("fetching file from %s", u)

	span.SetAttributes(
		attribute.String("http.url", u),
		semconv.HTTPRequestMethodGet,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+strings.TrimSpace(token))
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func loadSciToken() (string, error) {
	if ts, ok := os.LookupEnv("BEARER_TOKEN"); ok {
		return ts, nil
	}
	fname := discoverTokenFile()
	if fname == "" {
		return "", fmt.Errorf("no token found")
	}
	data, err := os.ReadFile(fname)
	if err != nil {
		return "", fmt.Errorf("unable to read token from file %s: %w", fname, err)
	}
	return string(data), nil
}

func discoverTokenFile() string {
	if f, ok := os.LookupEnv("BEARER_TOKEN_FILE"); ok {
		return f
	}
	if d, ok := os.LookupEnv("XDG_RUNTIME_DIR"); ok {
		f := filepath.Join(d, fmt.Sprintf("/bt_u%d", os.Getuid()))
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	f := filepath.Join(os.TempDir(), fmt.Sprintf("/bt_u%d", os.Getuid()))
	if _, err := os.Stat(f); err == nil {
		return f
	}
	return ""
}

// Initializes an OTLP exporter, and configures the corresponding trace provider.
func initTracerProvider(ctx context.Context, res *resource.Resource) (func(context.Context) error, error) {
	// Set up a trace exporter
	traceExporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Register the trace exporter with a TracerProvider, using a batch
	// span processor to aggregate spans before export.
	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(tracerProvider)

	// Set global propagator to tracecontext (the default is no-op).
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Shutdown will flush any remaining spans and shut down the exporter.
	return tracerProvider.Shutdown, nil
}
