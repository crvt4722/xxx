package repo

import (
	"context"
	"slices"
	"strings"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
	"xorm.io/builder"
)

type RepoCodeVulns []*RepoCodeVuln
const (
	DetectedLabel = "Detected"
)

type RepoCodeVuln struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"INDEX"`
	BranchName  string             `xorm:"VARCHAR(255)"`
	CheckID     string             `xorm:"VARCHAR(255)"`
	Target      string             `xorm:"TEXT"`
	VulnClass   string             `xorm:"VARCHAR(255)"`
	Owasps      string             `xorm:"TEXT"`
	Cwes        string             `xorm:"TEXT"`
	Severity    string             `xorm:"VARCHAR(255)"`
	Message     string             `xorm:"TEXT"`
	Solution    string             `xorm:"TEXT"`
	CodeContent string             `xorm:"TEXT"`
	References  string             `xorm:"TEXT"`
	LastScanned timeutil.TimeStamp `xorm:"INDEX last_scanned"`
	Label       string             `xorm:"VARCHAR(50)"`
}

func init() {
	// Register the model with the database
	db.RegisterModel(new(RepoCodeVuln))
}

type RepoCodeVulnSearchOptions struct {
	db.ListOptions
	RepoCodeVuln
	Q string
}

func (opts RepoCodeVulnSearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_code_vuln.repo_id": opts.RepoID})
	}
	if opts.VulnClass != "" {
		cond = cond.And(builder.Eq{"repo_code_vuln.vuln_class": opts.VulnClass})
	}
	if opts.Target != "" {
		cond = cond.And(builder.Eq{"repo_code_vuln.target": opts.Target})
	}
	if opts.BranchName != "" {
		cond = cond.And(builder.Eq{"repo_code_vuln.branch_name": opts.BranchName})
	}
	if opts.Severity != "" {
		cond = cond.And(builder.Eq{"repo_code_vuln.severity": opts.Severity})
	}
	if opts.Q != "" {
		cond = cond.And(builder.Like{"LOWER(repo_code_vuln.check_id)", opts.Q})
	}
	return cond
}

// GetRepoCodeVuln retrieves a code vulnerability by its ID
func GetRepoCodeVuln(ctx context.Context, ID int64) (*RepoCodeVuln, error) {
	var codeVuln RepoCodeVuln
	exists, err := db.GetEngine(ctx).Where("id = ?", ID).Get(&codeVuln)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &codeVuln, nil
}

// GetExistRepoCodeVuln retrieves an existing code vulnerability
func GetExistRepoCodeVuln(ctx context.Context, repoID int64, checkID, target, codeContent, branchName string) (*RepoCodeVuln, error) {
	var codeVuln RepoCodeVuln
	exists, err := db.GetEngine(ctx).
		Where("check_id = ?", checkID).
		And("repo_id = ?", repoID).
		And("target = ?", target).
		And("branch_name = ?", branchName).
		And("code_content = ?", codeContent).
		Get(&codeVuln)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &codeVuln, nil
}

// ListRepoCodeVulns retrieves all code vulnerabilities for a repository
func ListRepoCodeVulns(ctx context.Context, repoID int64, filter map[string]string) (RepoCodeVulns, error) {
	opts := RepoCodeVulnSearchOptions{
		RepoCodeVuln: RepoCodeVuln{
			RepoID:     repoID,
			VulnClass:  "",
			Target:     "",
			Severity:   "",
			BranchName: "",
		},
		ListOptions: db.ListOptions{
			ListAll: true,
		},
		Q: "",
	}
	if filter != nil {
		if filter["q"] != "" {
			opts.Q = "%" + strings.ToLower(filter["q"]) + "%"
		}
		if filter["location"] != "" {
			opts.Target = filter["location"]
		}
		if filter["vuln_class"] != "" {
			opts.VulnClass = filter["vuln_class"]
		}
		if filter["severity"] != "" {
			opts.Severity = filter["severity"]
		}
		if filter["branch_name"] != "" {
			opts.BranchName = filter["branch_name"]
		}
	}

	codeVulns, _, err := db.FindAndCount[RepoCodeVuln](ctx, opts)

	if err != nil {
		return nil, err
	}
	return codeVulns, nil
}

func GetListCodeVulnFilter(ctx context.Context, repoID int64) map[string][]string {
	res := map[string][]string{
		"location":    {},
		"vuln_class":  {},
		"severity":    {},
		"branch_name": {},
	}
	results := RepoCodeVulns{}
	if err := db.GetEngine(ctx).Distinct("target", "vuln_class", "severity", "branch_name").Where("repo_id = ?", repoID).Find(&results); err == nil {
		for _, bean := range results {
			if !slices.Contains(res["location"], bean.Target) {
				res["location"] = append(res["location"], bean.Target)
			}
			if !slices.Contains(res["vuln_class"], bean.VulnClass) {
				res["vuln_class"] = append(res["vuln_class"], bean.VulnClass)
			}
			if !slices.Contains(res["severity"], bean.Severity) {
				res["severity"] = append(res["severity"], bean.Severity)
			}
			if !slices.Contains(res["branch_name"], bean.BranchName) {
				res["branch_name"] = append(res["branch_name"], bean.BranchName)
			}
		}
	}
	return res
}

// CreateOrUpdateRepoCodeVuln creates a code vulnerability or updates an existing one
func CreateOrUpdateRepoCodeVuln(ctx context.Context, repoID int64, checkID, target, vulnClass, owasps, cwes, severity, message, solution,
	branchName, codeContent, references string, lastScanned timeutil.TimeStamp) (*RepoCodeVuln, error) {
	existingCodeVuln, err := GetExistRepoCodeVuln(ctx, repoID, checkID, target, codeContent, branchName)
	if err != nil {
		return nil, err
	}

	if existingCodeVuln == nil {
		// Create a new code vulnerability
		codeVuln := &RepoCodeVuln{
			CheckID:     checkID,
			RepoID:      repoID,
			BranchName:  branchName,
			Target:      target,
			VulnClass:   vulnClass,
			Owasps:      owasps,
			Cwes:        cwes,
			Severity:    severity,
			Message:     message,
			Solution:    solution,
			CodeContent: codeContent,
			References:  references,
			LastScanned: lastScanned,
			Label: DetectedLabel,
		}
		// Insert the new vulnerability into the database
		if err := db.Insert(ctx, codeVuln); err != nil {
			return nil, err
		}
		return codeVuln, nil
	} else {
		// Update the existing vulnerability
		existingCodeVuln.LastScanned = lastScanned
		if _, err := db.GetEngine(ctx).ID(existingCodeVuln.ID).Cols("last_scanned").Update(existingCodeVuln); err != nil {
			return nil, err
		}
		return existingCodeVuln, nil
	}
}

// UpdateCodeVulnLabel updates the specified label of a Dependency Vulnerability.
func UpdateCodeVulnLabel(ctx context.Context, ID int64, label string) error {
	existingVuln, _ := GetRepoCodeVuln(ctx, ID)
	existingVuln.Label = label

	if _, err := db.GetEngine(ctx).ID(ID).Cols("label").Update(existingVuln); err != nil {
		return err
	}

	return nil
}
