package arm64

// Decodable reports whether this CPU implements the instruction encoding raw.
// It is the filter the differential test uses to pick candidate encodings
// (there is no point comparing an instruction the interpreter rejects, since
// the rejection is itself the reported behavior), and it lets tooling census a
// binary for instructions this CPU would refuse.
func Decodable(raw uint32) bool {
	var in inst
	decode(&in, raw, 0)
	return in.fn != nil
}
