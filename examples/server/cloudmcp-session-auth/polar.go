package main

import (
	"context"
	"fmt"
	"log"
	"os"

	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
	"github.com/polarsource/polar-go/models/operations"
)

type PolarClient struct {
	client        *polargo.Polar
	meterBenefits []components.Benefit
	callMcpMeter  *components.Meter
	enabled       bool
}

func NewPolarClient() *PolarClient {
	accessToken := os.Getenv("POLAR_ACCESS_TOKEN")
	if accessToken == "" {
		log.Println("Warning: POLAR_ACCESS_TOKEN not set, Polar meter tracking disabled")
		return &PolarClient{enabled: false}
	}

	client := polargo.New(
		polargo.WithSecurity(accessToken),
	)

	pc := &PolarClient{
		client:  client,
		enabled: true,
	}

	// Initialize meter benefits and find the mcp-call meter
	if err := pc.initialize(); err != nil {
		log.Printf("Warning: Failed to initialize Polar client: %v", err)
		pc.enabled = false
	}

	return pc
}

func (pc *PolarClient) initialize() error {
	if !pc.enabled {
		return nil
	}

	ctx := context.Background()

	// Get meter benefits
	typeFilter := operations.CreateBenefitTypeFilterBenefitType(components.BenefitTypeMeterCredit)
	benefitsReq := operations.BenefitsListRequest{
		TypeFilter: &typeFilter,
	}

	benefitsResp, err := pc.client.Benefits.List(ctx, benefitsReq)
	if err != nil {
		return fmt.Errorf("failed to list benefits: %w", err)
	}

	if benefitsResp.ListResourceBenefit != nil {
		pc.meterBenefits = benefitsResp.ListResourceBenefit.Items
	}

	// Find the Cloud MCP Tool Calls meter
	metersReq := operations.MetersListRequest{
		Query: polargo.String("Cloud MCP Tool Calls"),
		Limit: polargo.Int64(1),
	}

	metersResp, err := pc.client.Meters.List(ctx, metersReq)
	if err != nil {
		return fmt.Errorf("failed to list meters: %w", err)
	}

	if metersResp.ListResourceMeter != nil && len(metersResp.ListResourceMeter.Items) > 0 {
		pc.callMcpMeter = &metersResp.ListResourceMeter.Items[0]
		log.Println("Polar \"mcp-call\" meter found!")
	} else {
		log.Println("Warning: No \"mcp-call\" meter found in Polar. Please ensure your Polar project is set up correctly.")
	}

	return nil
}

// CheckMeterBalance checks if the user has sufficient credits for a tool call
func (pc *PolarClient) CheckMeterBalance(ctx context.Context, userID string) error {
	if !pc.enabled || pc.callMcpMeter == nil {
		// If Polar is disabled or meter not found, allow the call
		return nil
	}

	// Skip check in test mode
	if os.Getenv("TEST_MODE") == "true" {
		return nil
	}

	if userID == "" {
		return fmt.Errorf("user ID is required for meter checking")
	}

	// Get customer state
	customerStateResp, err := pc.client.Customers.GetStateExternal(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get customer state: %w", err)
	}

	if customerStateResp.CustomerState == nil {
		return fmt.Errorf("no customer found for user %s", userID)
	}

	// Find the mcp-call meter in active meters
	var mcpCallMeter *components.CustomerStateMeter
	for _, meter := range customerStateResp.CustomerState.ActiveMeters {
		// Check if this meter ID matches any of our meter benefits
		for _, benefit := range pc.meterBenefits {
			// Check the type of benefit
			if benefit.BenefitMeterCredit != nil && benefit.BenefitMeterCredit.Properties.MeterID == meter.MeterID {
				mcpCallMeter = &meter
				break
			}
		}
		if mcpCallMeter != nil {
			break
		}
	}

	if mcpCallMeter == nil || mcpCallMeter.Balance <= 0 {
		return fmt.Errorf("insufficient credits. Please purchase more tool credits at CloudMCP.run to continue using this service")
	}

	return nil
}

// TrackUsage tracks a successful tool call
func (pc *PolarClient) TrackUsage(ctx context.Context, userID string) {
	if !pc.enabled || pc.callMcpMeter == nil {
		return
	}

	if userID == "" {
		log.Printf("Warning: Cannot track usage without user ID")
		return
	}

	// Create event for tracking
	event := components.EventCreateExternalCustomer{
		Name:               "mcp-call",
		ExternalCustomerID: userID,
	}

	// Wrap the event in the Events union type
	eventsWrapper := components.CreateEventsEventCreateExternalCustomer(event)

	eventsIngest := components.EventsIngest{
		Events: []components.Events{eventsWrapper},
	}

	resp, err := pc.client.Events.Ingest(ctx, eventsIngest)
	if err != nil {
		log.Printf("Failed to track usage event: %v", err)
		return
	}

	if resp.EventsIngestResponse != nil {
		log.Printf("Tracked usage event: %d event(s) for user %s", resp.EventsIngestResponse.Inserted, userID)
	}
}
