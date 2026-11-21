// ivar-control: the IVAR control plane.
//
//	ivar-control build    --source policy.yaml --keys k1.seed,k2.seed [--previous current.bundle] --out policy.bundle
//	ivar-control validate --source policy.yaml [--library replay-library]
//	    CI step: builds the policy, checks it in the core, and runs the attack
//	    replay library against it before release (section 8.2).
//	ivar-control serve    --bundle policy.bundle --tuf-keys dir --flags-key k.seed --operators ops.json --cosign cosign.pub
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jhmeel/ivar/go/controlplane"
	ivar "github.com/jhmeel/ivar/sdk/go"
)

func seedKey(path string) controlplane.PolicyKey {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != 32 {
		log.Fatalf("%s: need a 32 byte hex seed", path)
	}
	id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return controlplane.PolicyKey{ID: id, Priv: ed25519.NewKeyFromSeed(seed)}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ivar-control build|validate|serve")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	source := fs.String("source", "policy.yaml", "policy source")
	keys := fs.String("keys", "", "comma separated policy key seed files")
	previous := fs.String("previous", "", "bundle currently in force, to detect weakening")
	out := fs.String("out", "policy.bundle", "output bundle (base64 archive)")
	library := fs.String("library", "replay-library", "attack replay library")
	bundleFile := fs.String("bundle", "policy.bundle", "bundle to serve")
	tufDir := fs.String("tuf-keys", "", "directory with root1, root2, targets1, targets2, snapshot, timestamp seed files")
	flagsKey := fs.String("flags-key", "", "flags signing key seed file")
	operators := fs.String("operators", "", "operator public keys JSON {name: hex}")
	cosign := fs.String("cosign", "", "cosign public key PEM for plugins")
	listen := fs.String("listen", ":8090", "listen address")
	_ = fs.Parse(os.Args[2:])

	rt, err := ivar.Shared()
	if err != nil {
		log.Fatal(err)
	}
	switch os.Args[1] {
	case "build", "validate":
		src, err := controlplane.LoadSource(*source)
		if err != nil {
			log.Fatal(err)
		}
		if src.OperatorDecisions == "" {
			fmt.Fprintln(os.Stderr, "warning: no operator_decisions_file: the seven section 21 decisions are running on unconfirmed defaults")
		}
		content, err := controlplane.Build(rt, src, filepath.Dir(*source), time.Now())
		if err != nil {
			log.Fatal(err)
		}
		if *previous != "" {
			raw, _ := os.ReadFile(*previous)
			arch, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
			prev, err := controlplane.ReadArchive(arch)
			if err != nil {
				log.Fatal(err)
			}
			var reasons []string
			content, reasons, err = controlplane.MarkWeakening(prev.Content, content)
			if err != nil {
				log.Fatal(err)
			}
			for _, r := range reasons {
				fmt.Println("weakens protection:", r)
			}
		}
		if os.Args[1] == "validate" {
			tmp := filepath.Join(os.TempDir(), "ivar-policy.json")
			_ = os.WriteFile(tmp, content, 0o600)
			var out json.RawMessage
			if err := rt.Call("core.new", map[string]any{"policy": json.RawMessage(content), "redaction_key_hex": "00"}, 0, &out); err != nil {
				log.Fatalf("the core refuses this policy: %v", err)
			}
			cmd := exec.Command("ivar-replay-library", *library, tmp)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				log.Fatalf("attack replay library failed: %v", err)
			}
			fmt.Println("policy valid and the attack replay library passes")
			return
		}
		var pks []controlplane.PolicyKey
		for _, k := range strings.Split(*keys, ",") {
			if k != "" {
				pks = append(pks, seedKey(k))
			}
		}
		b, err := controlplane.Sign(content, pks)
		if err != nil {
			log.Fatal(err)
		}
		s, _ := b.ArchiveBase64()
		if err := os.WriteFile(*out, []byte(s), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("signed bundle written to %s with %d key(s)\n", *out, len(pks))
	case "serve":
		raw, err := os.ReadFile(*bundleFile)
		if err != nil {
			log.Fatal(err)
		}
		arch, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		b, err := controlplane.ReadArchive(arch)
		if err != nil {
			log.Fatal(err)
		}
		var meta struct {
			Version uint64 `json:"version"`
		}
		_ = json.Unmarshal(b.Content, &meta)
		ro := &controlplane.Rollout{}
		ro.Propose(controlplane.Release{Version: meta.Version, Archive64: strings.TrimSpace(string(raw))})
		tk := map[string][]ed25519.PrivateKey{}
		for _, f := range []string{"root1", "root2", "targets1", "targets2", "snapshot", "timestamp"} {
			k := seedKey(filepath.Join(*tufDir, f+".seed"))
			role := strings.TrimRight(f, "12")
			tk[role] = append(tk[role], k.Priv)
		}
		repo, err := controlplane.NewTUFRepo(tk, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		if err := repo.Publish("policy/current.bundle", arch, time.Now()); err != nil {
			log.Fatal(err)
		}
		go func() {
			for range time.Tick(6 * time.Hour) {
				_ = repo.Refresh(time.Now())
			}
		}()
		ops := map[string]ed25519.PublicKey{}
		if *operators != "" {
			var m map[string]string
			raw, _ := os.ReadFile(*operators)
			_ = json.Unmarshal(raw, &m)
			for k, v := range m {
				pk, _ := hex.DecodeString(v)
				ops[k] = pk
			}
		}
		var pems []string
		if *cosign != "" {
			p, _ := os.ReadFile(*cosign)
			pems = append(pems, string(p))
		}
		reg, err := controlplane.NewRegistry(pems)
		if err != nil {
			log.Fatal(err)
		}
		srv := &controlplane.Server{Rollout: ro, TUF: repo, Flags: controlplane.NewFlagStore(seedKey(*flagsKey), ops), Registry: reg}
		log.Printf("ivar control plane on %s serving policy version %d", *listen, meta.Version)
		log.Fatal((&http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
	}
}
