// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicodeploy

import (
	"time"

	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicorest"
	"github.com/dsx-ai-factory/nvke/cli/internal/bootstrap/nicosettings"
)

// Profile is which cluster NICo is installed on.
type Profile int

const (
	// ProfileSeed runs NICo in the Kind bootstrap cluster: one replica, Kind's
	// StorageClass, and every service on a fixed node port that Kind maps to
	// its address on the bootstrap host.
	ProfileSeed Profile = iota
	// ProfileSite runs NICo on the site cluster: the settings' replicas and
	// StorageClass, and every service on a LoadBalancer address MetalLB holds.
	ProfileSite
)

// Config is what differs between the clusters NICo is installed on.
type Config struct {
	// SiteName is the NICo site's name.
	SiteName string
	// Replicas is how many Vault and Postgres instances run. One on the
	// bootstrap cluster, which runs on a single host.
	Replicas int
	// StorageClass is the StorageClass Vault's and Postgres's volumes use.
	StorageClass string
	// Timeout bounds each wait. Zero means 15 minutes.
	Timeout time.Duration
	// ImageRegistry is the registry NICo's images are pulled from. NICo Core
	// runs ImageRegistry/nvmetal-carbide:CoreImageTag, and NICo REST runs its
	// images from ImageRegistry at RestImageTag.
	ImageRegistry string
	CoreImageTag  string
	RestImageTag  string
	// RegistryUsername and RegistryPassword log in to ImageRegistry. Without a
	// password the images are pulled anonymously. The username defaults to
	// $oauthtoken, NGC's.
	RegistryUsername string
	RegistryPassword string
	// CoreValues is NICo Core's site configuration, a values file in the format
	// of NICo's values/nico-core.yaml.
	CoreValues string
	// Settings is the NICo settings file the install follows.
	Settings *nicosettings.Settings
	// Secrets are the secrets the settings need.
	Secrets nicosettings.Secrets
	// Profile is the cluster NICo is installed on.
	Profile Profile
	// siteRootCarried is set when the site root CA was copied from the
	// bootstrap cluster, so the prerequisites use it instead of issuing one.
	siteRootCarried bool
}

// NewConfig returns the Config that installs NICo as settings describe on the
// cluster profile names. seedStorageClass is the bootstrap cluster's StorageClass.
func NewConfig(settings *nicosettings.Settings, secrets nicosettings.Secrets, profile Profile, seedStorageClass string) Config {
	cfg := Config{
		SiteName:         settings.SiteConfig.SiteName,
		Replicas:         1,
		StorageClass:     seedStorageClass,
		ImageRegistry:    settings.Images.Registry,
		CoreImageTag:     settings.Images.CoreTag,
		RestImageTag:     settings.Images.RestTag,
		RegistryUsername: secrets.RegistryUsername,
		RegistryPassword: secrets.RegistryPassword,
		CoreValues:       settings.CoreValues,
		Settings:         settings,
		Secrets:          secrets,
		Profile:          profile,
	}
	if profile == ProfileSite {
		cfg.Replicas = settings.EffectiveSiteReplicas()
		cfg.StorageClass = settings.Site.StorageClass
	}
	return cfg
}

// Installed is what an installed NICo is reached with.
type Installed struct {
	// SiteID is the NICo site's ID, the same on the bootstrap and the site cluster.
	SiteID string
	// RESTEndpoint is NICo REST's base URL at its published address.
	RESTEndpoint string
	// OrgID and APIName are the org and API name REST paths carry.
	OrgID   string
	APIName string
	// Credentials are the OAuth2 client nvkectl and CAPNICo fetch tokens with.
	Credentials nicorest.ClientCredentials
}

// REST returns a client of the installed NICo's REST API.
func (i *Installed) REST() *nicorest.Client {
	return nicorest.New(i.RESTEndpoint, i.OrgID, i.APIName, i.Credentials)
}
