package repo

import (
	"context"
	"slices"
	"strings"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
	"xorm.io/builder"
)

type RepoIacMisconfigurations []*RepoIacMisconfiguration

// RepoIacMisconfiguration defines the model for an IaC misconfiguration
type RepoIacMisconfiguration struct {
	ID          int64  `xorm:"pk autoincr"`  // Primary key, auto-increment
	VulnID      string `xorm:"VARCHAR(50)"`  // Unique ID for the misconfiguration
	AVDID       string `xorm:"VARCHAR(50)"`
	RepoID      int64  `xorm:"INDEX"`        // Repository ID
	BranchName  string `xorm:"VARCHAR(255)"`
	Type        string `xorm:"VARCHAR(50)"`  // Type of the misconfiguration
	Target      string `xorm:"VARCHAR(255)"` // Target affected by the misconfiguration
	Title       string `xorm:"TEXT"`         // Title of the misconfiguration
	Description string `xorm:"TEXT"`         // Description of the misconfiguration
	Message     string `xorm:"TEXT"`         // Detailed message about the issue
	Resolution  string `xorm:"TEXT"`         // Suggested resolution or fix
	Severity    string `xorm:"VARCHAR(50)"`  // Severity level (e.g., High, Medium)
	CodeContent string `xorm:"TEXT"`         // Relevant code snippet or content
	References  string `xorm:"TEXT"`         // Additional references
	LastScanned timeutil.TimeStamp `xorm:"INDEX NOT NULL last_scanned"`  // Last scanned date for the misconfiguration
}

// Register the model with the database
func init() {
	db.RegisterModel(new(RepoIacMisconfiguration))
}

type RepoIacMisconfigurationSearchOptions struct {
	db.ListOptions
	RepoIacMisconfiguration
	Q string
}

func (opts RepoIacMisconfigurationSearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_iac_misconfiguration.repo_id": opts.RepoID})
	}
	if opts.Type != "" {
		cond = cond.And(builder.Eq{"repo_iac_misconfiguration.type": opts.Type})
	}
	if opts.Target != "" {
		cond = cond.And(builder.Eq{"repo_iac_misconfiguration.target": opts.Target})
	}
	if opts.Severity != "" {
		cond = cond.And(builder.Eq{"repo_iac_misconfiguration.severity": opts.Severity})
	}
	if opts.BranchName != "" {
		cond = cond.And(builder.Eq{"repo_iac_misconfiguration.branch_name": opts.BranchName})
	}
	if opts.Q != "" {
		cond = cond.And(builder.Like{"LOWER(repo_iac_misconfiguration.title)", opts.Q})
	}
	return cond
}

// GetRepoIacMisconfiguration retrieves a misconfiguration by its ID
func GetRepoIacMisconfiguration(ctx context.Context, ID int64) (*RepoIacMisconfiguration, error) {
	var misconfig RepoIacMisconfiguration
	exists, err := db.GetEngine(ctx).Where("id = ?", ID).Get(&misconfig)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &misconfig, nil
}

// GetRepoIacMisconfigurationByVulnIDAndTarget retrieves a misconfiguration by its VulnID and Target
func GetRepoIacMisconfigurationByVulnIDAndTarget(ctx context.Context, vulnID, target, codeContent, branchName string) (*RepoIacMisconfiguration, error) {
	var misconfig RepoIacMisconfiguration
	exists, err := db.GetEngine(ctx).Where("vuln_id = ?", vulnID).And("target = ?", target).And("code_content = ?", codeContent).And("branch_name = ?", branchName).Get(&misconfig)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &misconfig, nil
}

// ListRepoIacMisconfigurations retrieves all misconfigurations for a repository
func ListRepoIacMisconfigurations(ctx context.Context, repoID int64, filter map[string]string) (RepoIacMisconfigurations, error) {
	opts := RepoIacMisconfigurationSearchOptions{
		RepoIacMisconfiguration: RepoIacMisconfiguration{
			RepoID:     repoID,
			Type:       "",
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
		if filter["type"] != "" {
			opts.Type = filter["type"]
		}
		if filter["severity"] != "" {
			opts.Severity = filter["severity"]
		}
		if filter["branch_name"] != "" {
			opts.BranchName = filter["branch_name"]
		}
	}

	misconfigs, _, err := db.FindAndCount[RepoIacMisconfiguration](ctx, opts)

	if err != nil {
		return nil, err
	}
	return misconfigs, nil
}

func GetListIaCFilter(ctx context.Context, repoID int64) map[string][]string {
	res := map[string][]string{
		"location":    {},
		"type":        {},
		"severity":    {},
		"branch_name": {},
	}
	results := RepoIacMisconfigurations{}
	if err := db.GetEngine(ctx).Distinct("target", "type", "severity", "branch_name").Where("repo_id = ?", repoID).Find(&results); err == nil {
		for _, bean := range results {
			if !slices.Contains(res["location"], bean.Target) {
				res["location"] = append(res["location"], bean.Target)
			}
			if !slices.Contains(res["type"], bean.Type) {
				res["type"] = append(res["type"], bean.Type)
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

// CreateOrUpdateRepoIacMisconfiguration creates a new misconfiguration or updates an existing one
func CreateOrUpdateRepoIacMisconfiguration(ctx context.Context, repoID int64, vulnID, avdID, misconfigType, target, title, description,
	message, resolution, severity, codeContent, references, branchName string, lastScanned timeutil.TimeStamp) (*RepoIacMisconfiguration, error) {
	// Check if the misconfiguration already exists
	existingMisconfig, err := GetRepoIacMisconfigurationByVulnIDAndTarget(ctx, vulnID, target, codeContent, branchName)
	if err != nil {
		return nil, err
	}

	if existingMisconfig == nil {
		// Create a new misconfiguration
		misconfig := &RepoIacMisconfiguration{
			VulnID:      vulnID,
			AVDID:       avdID,
			RepoID:      repoID,
			BranchName:  branchName,
			Type:        misconfigType,
			Target:      target,
			Title:       title,
			Description: description,
			Message:     message,
			Resolution:  resolution,
			Severity:    severity,
			CodeContent: codeContent,
			References:  references,
			LastScanned: lastScanned,
		}
		// Insert the new misconfiguration into the database
		if err := db.Insert(ctx, misconfig); err != nil {
			return nil, err
		}
		return misconfig, nil
	} else {
		// Update the existing misconfiguration
		existingMisconfig.LastScanned = lastScanned
		if _, err := db.GetEngine(ctx).ID(existingMisconfig.ID).Cols("last_scanned").Update(existingMisconfig); err != nil {
			return nil, err
		}
		return existingMisconfig, nil
	}
}

func GetTotalIacMisconfiguration(ctx context.Context, repoID int64) (int64, error) {
	repo, err := GetRepositoryByID(ctx, repoID)
	if err != nil {
		return 0, err
	}
	total, err := db.GetEngine(ctx).
		Where("repo_id = ?", repoID).
		And("branch_name = ?", repo.DefaultBranch).
		Count(&RepoIacMisconfiguration{})
	if err != nil {
		return 0, err
	}
	return total, nil
}
