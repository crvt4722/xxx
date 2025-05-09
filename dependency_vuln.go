package repo

import (
	"context"

	"code.gitea.io/gitea/models/db"
)

type RepoDependencyVulns []*RepoDependencyVuln

type RepoDependencyVuln struct {
	ID               int64   `xorm:"pk autoincr"`
	VulnID           string  `xorm:"VARCHAR(100)"`
	RepoID           int64   `xorm:"INDEX"`
	BranchName       string  `xorm:"VARCHAR(255)"`
	Type             string  `xorm:"VARCHAR(255)"`
	Target           string  `xorm:"VARCHAR(255)"`
	PkgName          string  `xorm:"VARCHAR(255)"`
	InstalledVersion string  `xorm:"VARCHAR(100)"`
	FixedVersion     string  `xorm:"VARCHAR(100)"`
	Status           string  `xorm:"VARCHAR(50)"`
	Severity         string  `xorm:"VARCHAR(50)"`
	CweIDs           string  `xorm:"VARCHAR(255)"`
	CvssScore        float64 `xorm:"DECIMAL(5,2)"`
	Title            string  `xorm:"VARCHAR(255)"`
	Description      string  `xorm:"TEXT"`
	PublishedAt      string  `xorm:"VARCHAR(50)"`
	LastModifiedAt   string  `xorm:"VARCHAR(50)"`
	References       string  `xorm:"TEXT"`
	Label            string  `xorm:"VARCHAR(50)"`
	LastScanned      string  `xorm:"VARCHAR(50)"`
}

func init() {
	db.RegisterModel(new(RepoDependencyVuln))
}

// GetDependencyVuln retrieves a list of vulnerabilities for a given repository and scan type.
func GetDependencyVuln(ctx context.Context, ID int64) (*RepoDependencyVuln, error) {
	var vuln RepoDependencyVuln
	existingVuln, err := db.GetEngine(ctx).Where("id=?", ID).Get(&vuln)
	if err != nil {
		// If there is an error during the database query, return nil and the error.
		return nil, err
	}

	if !existingVuln {
		return nil, nil
	}

	return &vuln, nil
}

func GetExistingDependencyVuln(ctx context.Context, repoID int64, vulnID, target, pkgName, installedVersion, branchName string) (*RepoDependencyVuln, error) {
	var vuln RepoDependencyVuln
	existingVuln, err := db.GetEngine(ctx).Where("repo_id = ?", repoID).And("vuln_id = ?", vulnID).And("installed_version = ?", installedVersion).And("target = ?", target).And("pkg_name = ?", pkgName).And("branch_name = ?", branchName).Get(&vuln)

	if err != nil {
		return nil, err
	}

	// If the vulnerability was found, return it; otherwise return nil
	if !existingVuln {
		return nil, nil
	}

	return &vuln, nil
}

// ListVulns retrieves a list of vulnerabilities for a given repository and scan type.
func ListDependencyVulns(ctx context.Context, repoID int64) (RepoDependencyVulns, error) {
	var vulns RepoDependencyVulns
	err := db.GetEngine(ctx).Where("repo_id=?", repoID).Find(&vulns)
	if err != nil {
		// If there is an error during the database query, return nil and the error.
		return nil, err
	}

	return vulns, nil
}

// UpdateDependencyVulnLabel updates the specified label of a Dependency Vulnerability.
func UpdateDependencyVulnLabel(ctx context.Context, ID int64, label string) error {
	existingVuln, _ := GetDependencyVuln(ctx, ID)
	existingVuln.Label = label
	if _, err := db.GetEngine(ctx).ID(ID).Cols("label").Update(existingVuln); err != nil {
		return err
	}

	return nil
}

// UpdateDependencyVuln updates the specified label of a Dependency Vulnerability.
func UpdateDependencyVuln(ctx context.Context, ID, repoID int64, severity, title, description, references, label string) (*RepoDependencyVuln, error) {

	existingVuln, _ := GetDependencyVuln(ctx, ID)
	if existingVuln == nil {
		return nil, nil
	}

	if severity != "" {
		existingVuln.Severity = severity
	}

	if title != "" {
		existingVuln.Title = title
	}

	if description != "" {
		existingVuln.Description = description
	}

	if references != "" {
		existingVuln.References = references
	}

	if label != "" {
		existingVuln.Label = label
	}

	if _, err := db.GetEngine(ctx).ID(ID).Update(existingVuln); err != nil {
		return nil, err
	}

	return existingVuln, nil
}

func CreateOrUpdateDependencyVuln(ctx context.Context, repoID int64, vulnID, target, dependency_type, pkgName, installedVersion,
	fixedVersion, status, severity, cweIDs, title, description, publishedAt, lastModifiedAt, references,
	label, lastScanned, branchName string, cvssScore float64) (*RepoDependencyVuln, error) {
	existingVuln, err := GetExistingDependencyVuln(ctx, repoID, vulnID, target, pkgName, installedVersion, branchName)
	if err != nil {
		return nil, err
	}

	if existingVuln == nil {
		vuln := &RepoDependencyVuln{
			VulnID:           vulnID,
			RepoID:           repoID,
			BranchName:       branchName,
			Target:           target,
			Type:             dependency_type,
			PkgName:          pkgName,
			InstalledVersion: installedVersion,
			FixedVersion:     fixedVersion,
			Status:           status,
			Severity:         severity,
			CweIDs:           cweIDs,
			CvssScore:        cvssScore,
			Title:            title,
			Description:      description,
			PublishedAt:      publishedAt,
			LastModifiedAt:   lastModifiedAt,
			References:       references,
			Label:            label,
			LastScanned:      lastScanned,
		}
		return vuln, db.Insert(ctx, vuln)
	} else {
		existingVuln.LastScanned = lastScanned
		if _, err := db.GetEngine(ctx).ID(existingVuln.ID).Cols("last_scanned").Update(existingVuln); err != nil {
			return nil, err
		}

		return existingVuln, nil
	}
}

func GetTotalDependencyVuln(ctx context.Context, repoID int64) (int64, error) {
	repo, err := GetRepositoryByID(ctx, repoID)
	if err != nil {
		return 0, err
	}
	total, err := db.GetEngine(ctx).
		Where("repo_id = ?", repoID).
		And("branch_name = ?", repo.DefaultBranch).
		Count(&RepoDependencyVuln{})
	if err != nil {
		return 0, err
	}
	return total, nil
}
