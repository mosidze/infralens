package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"infralens/internal/app"
	awsDiscovery "infralens/internal/aws"
	"infralens/internal/awswatch"
	"infralens/internal/engine"
	"infralens/internal/history"
	"infralens/internal/watch"
)

// monitorDailyBudget is what the monitor may spend on metered CloudWatch
// calls per day. Everything else it calls is free.
const monitorDailyBudget = 0.50

// monitorHook starts the Problem Monitor for a profile. It learns what exists
// from the profile's latest scan, so it does not have to rediscover the
// account, and it asks AWS only the cheap "what is wrong" questions.
func monitorHook(base, apiLogPath string) func(context.Context, app.MonitorSpec) (app.LiveSource, error) {
	return func(ctx context.Context, spec app.MonitorSpec) (app.LiveSource, error) {
		switch spec.Kind {
		case "aws":
			return startAWSMonitor(ctx, base, apiLogPath, spec.Name)
		case "k8s":
			return startK8sMonitor(ctx, base, spec)
		}
		return nil, fmt.Errorf("unknown monitor kind %q", spec.Kind)
	}
}

func startAWSMonitor(ctx context.Context, base, apiLogPath, profile string) (app.LiveSource, error) {
	{
		_, res, err := history.LatestForProfile(base, profile)
		if err != nil {
			return nil, fmt.Errorf("no scan of %q yet: run one first (the monitor uses it as its map)", profile)
		}
		dc := awsDiscovery.NewDiscoveryClient(profile, 4)
		if apiLogPath != "" {
			lf, err := os.OpenFile(apiLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				return nil, fmt.Errorf("api log: %w", err)
			}
			go func() { <-ctx.Done(); lf.Close() }()
			dc.Log = awsDiscovery.NewAPILog(lf, profile)
		}
		if _, err := dc.AccountID(ctx); err != nil {
			hint := "check the credentials"
			if strings.Contains(err.Error(), "SSO") || strings.Contains(err.Error(), "token") {
				hint = "run: aws sso login --profile " + profile
			}
			return nil, fmt.Errorf("cannot reach AWS with profile %q (%s)", profile, hint)
		}
		g := watch.NewGraph(res)
		tr := watch.NewTracker(3, 2)
		tr.SetNeed("elb", 2) // polled every five minutes
		tr.SetNeed("sqs", 1) // already compares two readings
		notesPath := filepath.Join(base, "context.json")
		r := &watch.Runner{
			Collectors: awswatch.Collectors(awswatch.Source{Clients: awswatch.NewClients(dc), Regions: g.Regions}),
			Tracker:    tr,
			Graph:      g,
			Budget:     watch.NewBudget(monitorDailyBudget),
			Interval:   30 * time.Second,
			Notes: func() engine.Context {
				c, _ := engine.LoadContext(notesPath)
				return c
			},
			Account: res.Account,
			Profile: profile,
			Stats:   dc.Log.Counts,
		}
		go r.Run(ctx)
		return r, nil
	}
}
