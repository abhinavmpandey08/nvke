// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package nicosettings

import "os"

// SecretsFromEnv reads the secrets s needs from the environment. Required: the
// site-wide BMC root password, the host and DPU UEFI passwords, each machine's
// <BMCLogin>_USERNAME and <BMCLogin>_PASSWORD. The DPU BMC factory login is
// optional but set as a pair, and required when DPUFactoryModels is set; the
// registry login and the BGP password are optional. The
// error names each missing variable, one per line, and never a value.
func SecretsFromEnv(s *Settings) (Secrets, error) {
	sec := Secrets{
		SiteWideBMCRootPassword: os.Getenv(SiteWideBMCRootPasswordEnv),
		HostUEFIPassword:        os.Getenv(HostUEFIPasswordEnv),
		DPUUEFIPassword:         os.Getenv(DPUUEFIPasswordEnv),
		DPUBMCFactoryUsername:   os.Getenv(DPUBMCFactoryUsernameEnv),
		DPUBMCFactoryPassword:   os.Getenv(DPUBMCFactoryPasswordEnv),
		RegistryUsername:        os.Getenv(RegistryUsernameEnv),
		RegistryPassword:        os.Getenv(RegistryPasswordEnv),
		BMCLogins:               map[string]Login{},
		BGPPassword:             os.Getenv(BGPPasswordEnv),
	}
	var p problems
	for _, r := range []struct{ env, value, why string }{
		{SiteWideBMCRootPasswordEnv, sec.SiteWideBMCRootPassword, "NICo sets it on every BMC it ingests"},
		{HostUEFIPasswordEnv, sec.HostUEFIPassword, "NICo sets it on every host"},
		{DPUUEFIPasswordEnv, sec.DPUUEFIPassword, "NICo sets it on every DPU"},
	} {
		if r.value == "" {
			p.addf("%s is not set: %s", r.env, r.why)
		}
	}
	if (sec.DPUBMCFactoryUsername == "") != (sec.DPUBMCFactoryPassword == "") {
		p.addf("%s and %s must be set together: they are one login", DPUBMCFactoryUsernameEnv, DPUBMCFactoryPasswordEnv)
	} else if sec.DPUBMCFactoryUsername == "" && len(s.DPUFactoryModels) > 0 {
		p.addf("%s and %s must be set: dpuFactoryModels names the DPU models they are for", DPUBMCFactoryUsernameEnv, DPUBMCFactoryPasswordEnv)
	}
	for _, m := range s.Machines {
		if _, seen := sec.BMCLogins[m.BMCLogin]; seen || m.BMCLogin == "" {
			continue
		}
		login := Login{Username: os.Getenv(m.BMCLogin + "_USERNAME"), Password: os.Getenv(m.BMCLogin + "_PASSWORD")}
		for _, v := range []struct{ suffix, value string }{{"_USERNAME", login.Username}, {"_PASSWORD", login.Password}} {
			if v.value == "" {
				p.addf("%s%s is not set: it is the BMC factory login of machine %s", m.BMCLogin, v.suffix, m.Name)
			}
		}
		sec.BMCLogins[m.BMCLogin] = login
	}
	if err := p.err(); err != nil {
		return Secrets{}, err
	}
	return sec, nil
}
