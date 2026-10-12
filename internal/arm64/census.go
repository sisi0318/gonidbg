//go:build census

// Build-tagged analysis helper, excluded from normal builds because it pulls in
// reflect and runtime symbol lookup. Used to study which handlers a real
// workload actually runs, and in which combinations, so that any decision to
// fuse instruction patterns is driven by measurement.
//
//	go run -tags census ./scratch/paircensus ...
package arm64

import (
	"reflect"
	"runtime"
	"strings"
)

// HandlerName names the handler that would execute encoding raw at pc, e.g.
// "opLdr64Off". Returns "<undefined>" for an encoding this CPU rejects.
func HandlerName(raw uint32, pc uint64) string {
	var in inst
	decode(&in, raw, pc)
	if in.fn == nil {
		return "<undefined>"
	}
	full := runtime.FuncForPC(reflect.ValueOf(in.fn).Pointer()).Name()
	if i := strings.LastIndexByte(full, '.'); i >= 0 {
		full = full[i+1:]
	}
	return full
}
