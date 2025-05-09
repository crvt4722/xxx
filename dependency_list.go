package repo

import (
	"context"
	"slices"
	"strings"

	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/modules/timeutil"
	"xorm.io/builder"
)

type RepoDependencyList []*RepoDependency

type RepoDependency struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"INDEX"`
	Type        string             `xorm:"VARCHAR(255)"`
	Target      string             `xorm:"VARCHAR(255)"`
	PkgName     string             `xorm:"VARCHAR(255)"`
	Version     string             `xorm:"VARCHAR(100)"`
	Licenses    string             `xorm:"VARCHAR(255)"`
	LastScanned timeutil.TimeStamp `xorm:"INDEX NOT NULL last_scanned"`
}

type RepoDependencySearchOptions struct {
	db.ListOptions
	RepoDependency
	Q string
}

func init() {
	db.RegisterModel(new(RepoDependency))
}

func (opts RepoDependencySearchOptions) ToConds() builder.Cond {
	cond := builder.NewCond()
	if opts.RepoID != 0 {
		cond = cond.And(builder.Eq{"repo_dependency.repo_id": opts.RepoID})
	}
	if opts.Target != "" {
		cond = cond.And(builder.Eq{"repo_dependency.target": opts.Target})
	}
	if opts.Licenses != "" {
		cond = cond.And(builder.Eq{"repo_dependency.licenses": opts.Licenses})
	}
	if opts.Q != "" {
		cond = cond.And(builder.Like{"LOWER(repo_dependency.pkg_name)", opts.Q})
	}
	return cond
}

// GetRepoDependency get a dependency information of the specified indentifier.
func GetRepoDependency(ctx context.Context, ID int64) (*RepoDependency, error) {
	var dependency RepoDependency
	existingDependency, err := db.GetEngine(ctx).Where("id=?", ID).Get(&dependency)
	if err != nil {
		// If there is an error during the database query, return nil and the error.
		return nil, err
	}

	if !existingDependency {
		return nil, nil
	}

	return &dependency, nil
}

func GetExistingDependency(ctx context.Context, repoID int64, target, pkgName, version string) (*RepoDependency, error) {
	var dependency RepoDependency
	existingVuln, err := db.GetEngine(ctx).Where("repo_id = ?", repoID).And("version = ?", version).And("target = ?", target).And("pkg_name = ?", pkgName).Get(&dependency)

	if err != nil {
		return nil, err
	}

	// If the dependency was found, return it; otherwise return nil
	if !existingVuln {
		return nil, nil
	}

	return &dependency, nil
}

// GetDependencyList retrieves a list of dependencies for a given repository.
func GetDependencyList(ctx context.Context, repoID int64, filter map[string]string) (RepoDependencyList, error) {
	opts := RepoDependencySearchOptions{
		RepoDependency: RepoDependency{
			RepoID:   repoID,
			Target:   "",
			Licenses: "",
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
		if filter["licenses"] != "" {
			opts.Licenses = filter["licenses"]
		}
	}
	dependencyList, _, err := db.FindAndCount[RepoDependency](ctx, opts)

	if err != nil {
		return nil, err
	}
	return dependencyList, nil
}

func GetListDependencyFilter(ctx context.Context, repoID int64) map[string][]string {
	res := map[string][]string{
		"location": {},
		"licenses": {},
	}
	results := RepoDependencyList{}
	if err := db.GetEngine(ctx).Distinct("target", "licenses").Where("repo_id = ?", repoID).Find(&results); err == nil {
		for _, bean := range results {
			if !slices.Contains(res["location"], bean.Target) {
				res["location"] = append(res["location"], bean.Target)
			}
			if !slices.Contains(res["licenses"], bean.Licenses) {
				res["licenses"] = append(res["licenses"], bean.Licenses)
			}
		}
	}
	return res
}

// CreateOrUpdateDependency add or update new Dependency .
func CreateOrUpdateDependency(ctx context.Context, repoID int64, target, dependency_type, pkgName, version,
	licenses string, lastScanned timeutil.TimeStamp) (*RepoDependency, error) {
	existingVuln, err := GetExistingDependency(ctx, repoID, target, pkgName, version)
	if err != nil {
		return nil, err
	}

	if existingVuln == nil {
		vuln := &RepoDependency{
			RepoID:      repoID,
			Target:      target,
			Type:        dependency_type,
			PkgName:     pkgName,
			Version:     version,
			Licenses:    licenses,
			LastScanned: lastScanned,
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

// DeleteDependencyByLastScanned deletes dependencies scanned which do not match the last scan.
func DeleteDependencyByLastScanned(ctx context.Context, repoID int64, lastScanned timeutil.TimeStamp) error {
	// Delete rows where the `repo_id` matches but the `last_scanned` does not.
	_, err := db.GetEngine(ctx).
		Where("repo_id = ? AND last_scanned != ?", repoID, lastScanned).
		Delete(new(RepoDependency))
	if err != nil {
		// Return the error if the deletion fails.
		return err
	}

	return nil
}
