// Package ivar is the IVAR application SDK for Go: net/http middleware over
// the verified decision core, loaded as WebAssembly with wazero.
package ivar

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed wasm/ivar_core.wasm
var coreWasm []byte

// Runtime is one WebAssembly instance of the core. Calls are serialised.
type Runtime struct {
	mu    sync.Mutex
	ctx   context.Context
	mod   api.Module
	alloc api.Function
	free  api.Function
	call  api.Function
}

var (
	shared     *Runtime
	sharedErr  error
	sharedOnce sync.Once
)

// Shared returns the process wide runtime.
func Shared() (*Runtime, error) {
	sharedOnce.Do(func() { shared, sharedErr = NewRuntime(context.Background()) })
	return shared, sharedErr
}

// NewRuntime compiles and instantiates the core.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	compiled, err := r.CompileModule(ctx, coreWasm)
	if err != nil {
		return nil, fmt.Errorf("compile core: %w", err)
	}
	cfg := wazero.NewModuleConfig().WithStartFunctions("_initialize").WithSysWalltime().WithSysNanotime().WithRandSource(cryptoRand{})
	mod, err := r.InstantiateModule(ctx, compiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiate core: %w", err)
	}
	return &Runtime{ctx: ctx, mod: mod, alloc: mod.ExportedFunction("ivar_alloc"), free: mod.ExportedFunction("ivar_free"), call: mod.ExportedFunction("ivar_call")}, nil
}

// Error is an error returned by the core.
type Error struct{ Message string }

func (e *Error) Error() string { return "ivar: " + e.Message }

// Call sends one JSON request to the core and decodes the response into out.
func (r *Runtime) Call(op string, args any, handle uint64, out any) error {
	req := map[string]any{"op": op, "args": args}
	if handle != 0 {
		req["handle"] = handle
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r.mu.Lock()
	raw, err := r.invoke(data)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	var e struct {
		Error *string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != nil {
		return &Error{Message: *e.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (r *Runtime) invoke(data []byte) ([]byte, error) {
	res, err := r.alloc.Call(r.ctx, uint64(len(data)))
	if err != nil {
		return nil, err
	}
	ptr := uint32(res[0])
	if !r.mod.Memory().Write(ptr, data) {
		return nil, errors.New("ivar: write out of range")
	}
	packed, err := r.call.Call(r.ctx, uint64(ptr), uint64(len(data)))
	if err != nil {
		return nil, err
	}
	_, _ = r.free.Call(r.ctx, uint64(ptr), uint64(len(data)))
	outPtr, outLen := uint32(packed[0]>>32), uint32(packed[0])
	view, ok := r.mod.Memory().Read(outPtr, outLen)
	if !ok {
		return nil, errors.New("ivar: read out of range")
	}
	out := append([]byte(nil), view...)
	n := outLen
	if n == 0 {
		n = 1
	}
	_, _ = r.free.Call(r.ctx, uint64(outPtr), uint64(n))
	return out, nil
}
