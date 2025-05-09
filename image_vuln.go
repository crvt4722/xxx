package repo

import (
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
	"context"
	"slices"
	"strings"
	"xorm.io/builder"
)

type RepoImageVulns []*RepoImageVuln

type RepoImageVuln struct {
	ID             int64              `xorm:"pk autoincr"` // Primary key, auto-increment
	VulnID         string             `xorm:"VARCHAR(50)"` // Unique ID for the misconfiguration
	RepoID         int64              `xorm:"INDEX"`       // Repository ID
	BranchName     string             `xorm:"VARCHAR(255)"`
	ImageVulnTitle string             `xorm:"VARCHAR(255)"`
	Description    string             `xorm:"TEXT"`         // Description of the misconfiguration
	Severity       string             `xorm:"VARCHAR(255)"` // Severity level (e.g., High, Medium)
	PkgName        string             `xorm:"VARCHAR(255)"`
	Version        string             `xorm:"VARCHAR(255)"`
	Type           string             `xorm:"VARCHAR(50)"`  // Type of the misconfiguration
	Target         string             `xorm:"VARCHAR(255)"` // Target affected by the misconfiguration
	Status         string             `xorm:"TEXT"`         // Title of the misconfiguration
	CreatedTime    timeutil.TimeStamp `xorm:"INDEX created_time"`
	UpdatedTime    timeutil.TimeStamp `xorm:"INDEX updated_time"`
	References     string             `xorm:"TEXT"` // Additional references
	LastScanned    timeutil.TimeStamp `xorm:"INDEX NOT NULL last_scanned"`
}

// Register the model with the database
func init() {
	db.RegisterModel(new(RepoImageVuln))
}

type RepoImageVulnSearchOptions struct {
	db.ListOptions
	RepoImageVuln
	Q string
}

func (opts RepoImageVulnSearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_image_vuln.repo_id": opts.RepoID})
	}
	if opts.Target != "" {
		cond = cond.And(builder.Eq{"repo_image_vuln.target": opts.Target})
	}
	if opts.Severity != "" {
		cond = cond.And(builder.Eq{"repo_image_vuln.severity": opts.Severity})
	}
	if opts.BranchName != "" {
		cond = cond.And(builder.Eq{"repo_image_vuln.branch_name": opts.BranchName})
	}
	if opts.Q != "" {
		cond = cond.And(builder.Like{"LOWER(repo_image_vuln.image_vuln_title)", opts.Q})
	}
	return cond
}

func GetRepoImageVuln(ctx context.Context, ID int64) (*RepoImageVuln, error) {
	var imageVuln RepoImageVuln
	existingVuln, err := db.GetEngine(ctx).Where("id=?", ID).Get(&imageVuln)
	if err != nil {
		return nil, err
	}

	if !existingVuln {
		return nil, nil
	}
	return &imageVuln, nil
}

func GetExistRepoImageVuln(ctx context.Context, repoID int64, vulnID, imageVulnTitle, version, pkgName, target,
	branchName string) (*RepoImageVuln, error) {
	var imageVuln RepoImageVuln
	exists, err := db.GetEngine(ctx).Where("repo_id = ?", repoID).And("target = ?", target).And("vuln_id = ?", vulnID).
		And("image_vuln_title = ?", imageVulnTitle).And("version = ?", version).And("pkg_name = ?", pkgName).
		And("branch_name = ?", branchName).Get(&imageVuln)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	return &imageVuln, nil
}

func CreateOrUpdateRepoImageVuln(ctx context.Context, repoID int64, vulnID, imageVulnTitle, target, serverity,
	description, version, status, references, pkgName, imageType, branchName string,
	createdTime, updatedTime, lastScanned timeutil.TimeStamp) (*RepoImageVuln, error) {
	existingImageVuln, err := GetExistRepoImageVuln(ctx, repoID, vulnID, imageVulnTitle, version, pkgName, target, branchName)
	if err != nil {
		return nil, err
	}

	if existingImageVuln == nil {
		imageVuln := &RepoImageVuln{
			VulnID:         vulnID,
			RepoID:         repoID,
			ImageVulnTitle: imageVulnTitle,
			BranchName:     branchName,
			Target:         target,
			Severity:       serverity,
			LastScanned:    lastScanned,
			Description:    description,
			Status:         status,
			References:     references,
			CreatedTime:    createdTime,
			UpdatedTime:    updatedTime,
			Version:        version,
			PkgName:        pkgName,
			Type:           imageType,
		}
		if err := db.Insert(ctx, imageVuln); err != nil {
			return nil, err
		}
		return imageVuln, nil
	} else {
		existingImageVuln.UpdatedTime = updatedTime
		existingImageVuln.LastScanned = lastScanned
		if _, err := db.GetEngine(ctx).ID(existingImageVuln.ID).Cols("updated_time").Cols("last_scanned").Update(existingImageVuln); err != nil {
			return nil, err
		}
		return existingImageVuln, nil
	}
}

func ListRepoImageVulns(ctx context.Context, repoID int64, filter map[string]string) (RepoImageVulns, error) {
	opts := RepoImageVulnSearchOptions{
		RepoImageVuln: RepoImageVuln{
			RepoID:     repoID,
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
		if filter["severity"] != "" {
			opts.Severity = filter["severity"]
		}
		if filter["branch_name"] != "" {
			opts.BranchName = filter["branch_name"]
		}
	}

	imageVuln, _, err := db.FindAndCount[RepoImageVuln](ctx, opts)
	if err != nil {
		return nil, err
	}
	return imageVuln, nil
}

func GetListImageVulnFilter(ctx context.Context, repoID int64) map[string][]string {
	res := map[string][]string{
		"location":    {},
		"severity":    {},
		"branch_name": {},
	}
	results := RepoImageVulns{}
	if err := db.GetEngine(ctx).Distinct("target", "severity", "branch_name").Where("repo_id = ?", repoID).Find(&results); err == nil {
		for _, bean := range results {
			if !slices.Contains(res["location"], bean.Target) {
				res["location"] = append(res["location"], bean.Target)
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

func UpdateImageVuln(ctx context.Context, ID, repoID int64, status, description, title, severity string) (*RepoImageVuln, error) {
	existingImageVuln, _ := GetRepoImageVuln(ctx, ID)
	if existingImageVuln == nil {
		return nil, nil
	}
	if severity != "" {
		existingImageVuln.Severity = severity
	}
	if status != "" {
		existingImageVuln.Status = status
	}
	if description != "" {
		existingImageVuln.Description = description
	}
	if title != "" {
		existingImageVuln.ImageVulnTitle = title
	}
	if _, err := db.GetEngine(ctx).ID(ID).Update(existingImageVuln); err != nil {
		return nil, err
	}

	return existingImageVuln, nil
}
