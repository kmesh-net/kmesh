package bpftests

//go:generate protoc --go_out=. trf.proto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/tools/cover"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"kmesh.net/kmesh/pkg/constants"
)

var (
	testPath = flag.String("bpf-test-path", "", "Path to the eBPF tests")
)

func TestBPF(t *testing.T) {
	if testPath == nil || *testPath == "" {
		t.Skip("Set -bpf-test-path to run BPF tests")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	entries, err := os.ReadDir(*testPath)
	if err != nil {
		t.Fatal("os readdir: ", err)
	}
	var instrLog io.Writer

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".o") {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			loadAndRunSpec(t, entry, instrLog)
		})
	}
}

func loadAndRunSpec(t *testing.T, entry fs.DirEntry, instrLog io.Writer) []*cover.Profile {
	elfPath := path.Join(*testPath, entry.Name())

	if instrLog != nil {
		fmt.Fprintln(instrLog, "===", elfPath, "===")
	}
	spec := loadAndPrepSpec(t, elfPath)

	t.Logf("spec programs:\n")
	for _, p := range spec.Programs {
		t.Logf("Program name:\t%s\tType:\t%s\tSectionName:\t%s\n", p.Name, p.Type, p.SectionName)
	}

	var (
		coll *ebpf.Collection // bpf程序load后的对象
		err  error
	)

	// Load the eBPF collection into the kernel
	coll, err = ebpf.NewCollection(spec)

	// Check for errors, specifically handle eBPF verifier errors separately
	// as they provide more detailed diagnostics
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier error: %+v", ve)
		} else {
			t.Fatal("loading collection:", err)
		}
	}
	defer coll.Close()

	// Register tail calls
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallPoliciesCheck, "policies_check")
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallPolicyCheck, "policy_check")
	registerTailCall(t, coll, xdpTailCallMap, constants.TailCallAuthInUserSpace, "xdp_shutdown_in_userspace")

	// Iterate through all programs and organize them by test name and function type
	// based on their section names matching the pattern "<test_name>/(check|setup|pktgen)"
	testNameToPrograms := make(map[string]programSet)
	for progName, spec := range spec.Programs {
		match := checkProgRegex.FindStringSubmatch(spec.SectionName)
		if len(match) == 0 {
			continue
		}

		progs := testNameToPrograms[match[1]]
		if match[2] == "pktgen" {
			progs.pktgenProg = coll.Programs[progName]
		}
		if match[2] == "setup" {
			progs.setupProg = coll.Programs[progName]
		}
		if match[2] == "check" {
			progs.checkProg = coll.Programs[progName]
		}
		testNameToPrograms[match[1]] = progs
	}

	// Ensure every test that has a setup program also has a check program
	for progName, set := range testNameToPrograms {
		if set.checkProg == nil {
			t.Fatalf(
				"File '%s' contains a setup program in section '%s' but no check program.",
				elfPath,
				progName,
			)
		}
	}

	// Collect debug events and add them as logs of the main test
	var globalLogReader *perf.Reader
	if m := coll.Maps["test_cilium_events"]; m != nil {
		globalLogReader, err = perf.NewReader(m, os.Getpagesize()*16)
		if err != nil {
			t.Fatalf("new global log reader: %s", err.Error())
		}
		defer globalLogReader.Close()

		go func() {
			for {
				rec, err := globalLogReader.Read()
				if err != nil {
					return
				}

				reader := bytes.NewReader(rec.RawSample)
				dm := make([]byte, len(rec.RawSample))
				if err := binary.Read(reader, binary.LittleEndian, &dm); err != nil {
					return
				}

				t.Log(dm)
			}
		}()
	}

	// Make sure sub-tests are executed in alphabetic order, to make test results repeatable if programs rely on
	// the order of execution.
	testNames := make([]string, 0, len(testNameToPrograms))
	for name := range testNameToPrograms {
		testNames = append(testNames, name)
	}
	slices.Sort(testNames)

	// Get maps used for common mocking facilities
	// todo(tzx): 适配kmesh
	skbMdMap := coll.Maps[mockSkbMetaMap]

	// run the test
	for _, name := range testNames {
		t.Run(name, subTest(testNameToPrograms[name], coll.Maps[suiteResultMap], skbMdMap))
	}

	return nil
}

// loadAndPrepSpec loads an eBPF Collection Specification from the provided ELF file
// and prepares it for testing. It disables pinning for all maps to avoid interference
// between tests. Additionally, it filters out programs that don't support BPF_PROG_RUN,
// keeping only XDP, SchedACT, and SchedCLS type programs.
//
// Parameters:
//   - t: The testing context, used for logging and reporting failures
//   - elfPath: Path to the ELF file containing the eBPF program
//
// Returns:
//   - *ebpf.CollectionSpec: The prepared collection specification
//
// The function will call t.Fatalf if loading the specification fails.
func loadAndPrepSpec(t *testing.T, elfPath string) *ebpf.CollectionSpec {

	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("load spec %s: %v", elfPath, err)
	}

	// Unpin all maps, as we don't want to interfere with other tests
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	for n, p := range spec.Programs {
		switch p.Type {
		// https://docs.ebpf.io/linux/syscall/BPF_PROG_TEST_RUN/
		case ebpf.XDP, ebpf.SchedACT, ebpf.SchedCLS, ebpf.SocketFilter, ebpf.CGroupSKB:
			continue
		}

		t.Logf("Skipping program '%s' of type '%s': BPF_PROG_RUN not supported", p.Name, p.Type)
		delete(spec.Programs, n)
	}

	return spec
}

// registerTailCall registers a tail call in the eBPF collection by updating the specified
// tail call map at the given index with the file descriptor of the named program.
//
// Parameters:
//   - t: Testing context for logging and error reporting
//   - coll: eBPF collection containing maps and programs
//   - tail_call_map_name: Name of the tail call map to update
//   - index: Index in the map where the program reference should be stored
//   - tail_call_prog_name: Name of the program to be called
//
// If the map or program is not found in the collection, the function logs the issue and
// continues without error. This is expected behavior when testing modules that don't
// require the specific tail call functionality.
//
// The function will only fail the test if the map and program exist but the update operation
// encounters an error.
func registerTailCall(t *testing.T, coll *ebpf.Collection, tail_call_map_name string, index uint32, tail_call_prog_name string) {
	if tailCallMap, ok := coll.Maps[tail_call_map_name]; ok {
		if prog, ok := coll.Programs[tail_call_prog_name]; ok {
			if err := tailCallMap.Update(
				index,
				uint32(prog.FD()),
				ebpf.UpdateAny); err != nil {
				t.Fatalf("Failed to register tail call: %v", err)
			}
			t.Logf("Successfully registered tail call %s -> %s[%d]", tail_call_prog_name, tail_call_map_name, index)
		} else {
			t.Logf("Program %s not found in collection", tail_call_prog_name)
		}
	} else {
		t.Logf("Map %s not found in collection", tail_call_map_name)
	}
}

type programSet struct {
	pktgenProg *ebpf.Program
	setupProg  *ebpf.Program
	checkProg  *ebpf.Program
}

var checkProgRegex = regexp.MustCompile(`[^/]+/test/([^/]+)/((?:check)|(?:setup)|(?:pktgen))`)

const (
	ResultSuccess = 1

	suiteResultMap = "suite_result_map"
	mockSkbMetaMap = "mock_skb_meta_map"
	xdpTailCallMap = "km_xdp_tailcall"
)

func subTest(progSet programSet, resultMap *ebpf.Map, skbMdMap *ebpf.Map) func(t *testing.T) {
	return func(t *testing.T) {
		// create ctx with the max allowed size(4k - head room - tailroom)
		data := make([]byte, 4096-256-320)

		// ctx is only used for tc programs
		// non-empty ctx passed to non-tc programs will cause error: invalid argument
		ctx := make([]byte, 0)
		if progSet.checkProg.Type() == ebpf.SchedCLS {
			// sizeof(struct __sk_buff) < 256, let's make it 256
			ctx = make([]byte, 256)
		}

		var (
			statusCode uint32
			err        error
		)
		if progSet.pktgenProg != nil {
			if statusCode, data, ctx, err = runBpfProgram(progSet.pktgenProg, data, ctx); err != nil {
				t.Fatalf("error while running pktgen prog: %s", err)
			}

		}

		if progSet.setupProg != nil {
			if statusCode, data, ctx, err = runBpfProgram(progSet.setupProg, data, ctx); err != nil {
				t.Fatalf("error while running setup prog: %s", err)
			}

			status := make([]byte, 4)
			nl.NativeEndian().PutUint32(status, statusCode)
			data = append(status, data...)
		}

		// Run test
		if statusCode, data, ctx, err = runBpfProgram(progSet.checkProg, data, ctx); err != nil {
			t.Fatal("error while running check program:", err)
		}

		// Clear map value after each test
		defer func() {
			for _, m := range []*ebpf.Map{resultMap, skbMdMap} {
				if m == nil {
					continue
				}

				var key int32
				value := make([]byte, m.ValueSize())
				m.Lookup(&key, &value)
				for i := 0; i < len(value); i++ {
					value[i] = 0
				}
				m.Update(&key, &value, ebpf.UpdateAny)
			}
		}()

		var key int32
		value := make([]byte, resultMap.ValueSize())
		err = resultMap.Lookup(&key, &value)
		if err != nil {
			t.Fatal("error while getting suite result:", err)
		}

		// Detect the length of the result, since the proto.Unmarshal doesn't like trailing zeros.
		valueLen := 0
		valueC := value
		for {
			_, _, len := protowire.ConsumeField(valueC)
			if len <= 0 {
				break
			}
			valueLen += len
			valueC = valueC[len:]
		}

		result := &SuiteResult{}
		err = proto.Unmarshal(value[:valueLen], result)
		if err != nil {
			t.Fatal("error while unmarshalling suite result:", err)
		}

		for _, testResult := range result.Results {
			// Remove the C-string, null-terminator.
			name := strings.TrimSuffix(testResult.Name, "\x00")
			t.Run(name, func(tt *testing.T) {
				if len(testResult.TestLog) > 0 && testing.Verbose() || testResult.Status != SuiteResult_TestResult_PASS {
					for _, log := range testResult.TestLog {
						tt.Logf("%s", log.FmtString())
					}
				}

				switch testResult.Status {
				case SuiteResult_TestResult_ERROR:
					tt.Fatal("Test failed due to unknown error in test framework")
				case SuiteResult_TestResult_FAIL:
					tt.Fail()
				case SuiteResult_TestResult_SKIP:
					tt.Skip()
				}
			})
		}

		if len(result.SuiteLog) > 0 && testing.Verbose() ||
			SuiteResult_TestResult_TestStatus(statusCode) != SuiteResult_TestResult_PASS {
			for _, log := range result.SuiteLog {
				t.Logf("%s", log.FmtString())
			}
		}

		switch SuiteResult_TestResult_TestStatus(statusCode) {
		case SuiteResult_TestResult_ERROR:
			t.Fatal("Test failed due to unknown error in test framework")
		case SuiteResult_TestResult_FAIL:
			t.Fail()
		case SuiteResult_TestResult_SKIP:
			t.SkipNow()
		}
	}
}

// A simplified version of fmt.Printf logic, the meaning of % specifiers changed to match the kernels printk specifiers.
// In the eBPF code a user can for example call `test_log("expected 123, got %llu", some_val)` the %llu meaning
// long-long-unsigned translates into a uint64, the rendered out would for example be -> 'expected 123, got 234'.
// https://www.kernel.org/doc/Documentation/printk-formats.txt
// https://github.com/libbpf/libbpf/blob/4eb6485c08867edaa5a0a81c64ddb23580420340/src/bpf_helper_defs.h#L152
func (l *Log) FmtString() string {
	var sb strings.Builder

	end := len(l.Fmt)
	argNum := 0

	for i := 0; i < end; {
		lasti := i
		for i < end && l.Fmt[i] != '%' {
			i++
		}
		if i > lasti {
			sb.WriteString(strings.TrimSuffix(l.Fmt[lasti:i], "\x00"))
		}
		if i >= end {
			// done processing format string
			break
		}

		// Process one verb
		i++

		var spec []byte
	loop:
		for ; i < end; i++ {
			c := l.Fmt[i]
			switch c {
			case 'd', 'i', 'u', 'x', 's':
				spec = append(spec, c)
				break loop
			case 'l':
				spec = append(spec, c)
			default:
				break loop
			}
		}
		// Advance to to next char
		i++

		// No argument left over to print for the current verb.
		if argNum >= len(l.Args) {
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(MISSING)")
			continue
		}

		switch string(spec) {
		case "u":
			fmt.Fprint(&sb, uint16(l.Args[argNum]))
		case "d", "i", "s":
			fmt.Fprint(&sb, int16(l.Args[argNum]))
		case "x":
			hb := make([]byte, 2)
			binary.BigEndian.PutUint16(hb, uint16(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "lu":
			fmt.Fprint(&sb, uint32(l.Args[argNum]))
		case "ld", "li", "ls":
			fmt.Fprint(&sb, int32(l.Args[argNum]))
		case "lx":
			hb := make([]byte, 4)
			binary.BigEndian.PutUint32(hb, uint32(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "llu":
			fmt.Fprint(&sb, uint64(l.Args[argNum]))
		case "lld", "lli", "lls":
			fmt.Fprint(&sb, int64(l.Args[argNum]))
		case "llx":
			hb := make([]byte, 8)
			binary.BigEndian.PutUint64(hb, uint64(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		default:
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(INVALID)")
			continue
		}

		argNum++
	}

	return sb.String()
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	if len(dataOut) > 0 {
		// See comments at https://github.com/cilium/ebpf/blob/20c4d8896bdde990ce6b80d59a4262aa3ccb891d/prog.go#L563-L567
		dataOut = make([]byte, len(data)+256+2)
	}
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     1,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}
