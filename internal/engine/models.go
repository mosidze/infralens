package engine

import "time"

type ResourceStatus string

const (
	StatusManaged     ResourceStatus = "managed"
	StatusShadowIT    ResourceStatus = "shadow_it"
	StatusOrphanWaste ResourceStatus = "orphan_waste"
	StatusUnknown     ResourceStatus = "unknown"
)

type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

const (
	CostEstimated    = "estimated"
	CostNotAvailable = "n/a"
)

type CostHistory struct {
	PreviousMonthCost float64 `json:"previous_month_cost"`
	CurrentMonthCost  float64 `json:"current_month_cost"`
	TrendPct          float64 `json:"trend_pct"`
	PreviousMonthName string  `json:"previous_month_name"`
	CurrentMonthName  string  `json:"current_month_name"`
}

// Ack records that a person has seen a finding and decided it is expected
// (planned migration, intentional). It is data supplied by the user, never
// inferred, and it can lapse.
type Ack struct {
	Note  string `json:"note"`
	Until string `json:"until,omitempty"` // YYYY-MM-DD, empty = no expiry
}

// Commitment is a reservation, savings plan or a coverage fact. It carries
// facts and suggestions that are conditional on plans the tool cannot know.
type Commitment struct {
	Kind          string     `json:"kind"` // reservation | savings_plan | coverage
	Service       string     `json:"service"`
	ID            string     `json:"id,omitempty"`
	Region        string     `json:"region,omitempty"`
	Detail        string     `json:"detail,omitempty"`
	State         string     `json:"state,omitempty"`
	Start         *time.Time `json:"start,omitempty"`
	End           *time.Time `json:"end,omitempty"`
	CoveragePct   float64    `json:"coverage_pct,omitempty"`
	OnDemandHours float64    `json:"on_demand_hours,omitempty"`
	ReservedHours float64    `json:"reserved_hours,omitempty"`
	UnusedHours   float64    `json:"unused_hours,omitempty"`
	Facts         []string   `json:"facts,omitempty"`
	Suggestions   []string   `json:"suggestions,omitempty"`
	Ack           *Ack       `json:"ack,omitempty"`
}

// Dependent is something found that relies on a resource, or a fact that
// matters before removing it (such as the existence of a backup).
type Dependent struct {
	Kind   string `json:"kind"` // dns | cloudfront | route | consumer | cluster-member | backup
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

// BlastRadius says what removing a resource could affect. Checked lists the
// lookups that were actually performed, so an empty Dependents list means
// "looked, found none" and not "did not look". Unchecked lists lookups that
// could not run (missing permission).
type BlastRadius struct {
	Checked    []string    `json:"checked"`
	Unchecked  []string    `json:"unchecked,omitempty"`
	Dependents []Dependent `json:"dependents,omitempty"`
}

// ResourceNode is one discovered AWS resource.
type ResourceNode struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Group       string         `json:"group"`
	Status      ResourceStatus `json:"status"`
	Region      string         `json:"region"`
	VPCID       string         `json:"vpc_id,omitempty"`
	SubnetID    string         `json:"subnet_id,omitempty"`
	MonthlyCost float64        `json:"monthly_cost"`
	// ListCost is the catalogue-price estimate kept when MonthlyCost was
	// replaced by money allocated from the bill. CostBasis says where
	// MonthlyCost came from: allocated | estimated | n/a.
	ListCost  float64 `json:"list_cost,omitempty"`
	CostBasis string  `json:"cost_basis,omitempty"`
	CostNote  string  `json:"cost_note,omitempty"`
	// Drivers are measured quantities (hours, GB, requests) per month that the
	// bill is allocated by.
	Drivers     map[string]float64 `json:"drivers,omitempty"`
	CostSource  string             `json:"cost_source,omitempty"`
	WasteReason string             `json:"waste_reason,omitempty"`
	ManagedBy   string             `json:"managed_by,omitempty"`
	Confidence  Confidence         `json:"confidence,omitempty"`
	Evidence    []string           `json:"evidence,omitempty"`
	Attrs       map[string]string  `json:"attrs,omitempty"`
	Tags        map[string]string  `json:"tags,omitempty"`
	Ack         *Ack               `json:"ack,omitempty"`
	Blast       *BlastRadius       `json:"blast,omitempty"`
	// Owner is who the resource is attributed to and where that came from.
	Owner       string `json:"owner,omitempty"`
	OwnerSource string `json:"owner_source,omitempty"`
	// IaC says which state file or stack holds the resource, when one was
	// read. Absent means "not found in what was read", not "unmanaged".
	IaC *IaCInfo `json:"iac,omitempty"`
}

// Edge is a dependency between two nodes, by node ID.
type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
}

// ServiceCost is the account-level Cost Explorer figure for one AWS service.
type ServiceCost struct {
	Service string `json:"service"`
	CostHistory
	// Scanned says whether any scanner covers this service; Estimated is the
	// sum of node estimates mapped to it (steady-state monthly, list price).
	Scanned   bool    `json:"scanned"`
	Estimated float64 `json:"estimated"`
}

type ScanResult struct {
	Timestamp time.Time `json:"timestamp"`
	Profile   string    `json:"profile"`
	// Account is the AWS account ID, the stable key for scan history.
	Account string `json:"account,omitempty"`
	// CoveredTypes are the node types the run's checks could produce. A diff
	// only compares types covered by both runs, so a partial scan does not
	// look like mass deletion.
	CoveredTypes []string `json:"covered_types,omitempty"`
	// TypeServices maps node type to the Cost Explorer service it bills under,
	// so a viewer can apportion the billed amount over the resources.
	TypeServices map[string]string `json:"type_services,omitempty"`
	Diff         *Diff             `json:"diff,omitempty"`
	Regions      []string          `json:"regions"`
	Nodes        []ResourceNode    `json:"nodes"`
	Edges        []Edge            `json:"edges"`
	ServiceCosts []ServiceCost     `json:"service_costs,omitempty"`
	Warnings     []string          `json:"warnings,omitempty"`
	Skipped      []string          `json:"skipped,omitempty"`
	TotalLive    int               `json:"total_live"`
	WasteCount   int               `json:"waste_count"`
	// Acknowledged waste candidates are excluded from WasteCount/TotalWaste.
	AckedCount    int          `json:"acked_count,omitempty"`
	AckedWaste    float64      `json:"acked_waste,omitempty"`
	Commitments   []Commitment `json:"commitments,omitempty"`
	Findings      []Finding    `json:"findings,omitempty"`
	Ledger        *Ledger      `json:"ledger,omitempty"`
	IaC           *IaCSummary  `json:"iac,omitempty"`
	TotalWaste    float64      `json:"total_waste"`
	ShadowCount   int          `json:"shadow_count"`
	EstimatedTCO  float64      `json:"estimated_tco"`
	TotalPrevCost float64      `json:"total_prev_cost"`
	TotalCurrCost float64      `json:"total_curr_cost"`
	Summary       string       `json:"summary,omitempty"`
	// Checks are the scanners that ran and IdleWindowDays the idle window they
	// used, so a report can state its own method.
	Checks         []string `json:"checks,omitempty"`
	IdleWindowDays int      `json:"idle_window_days,omitempty"`
	AIAnalysis     string   `json:"ai_analysis,omitempty"`
}
