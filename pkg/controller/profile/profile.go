package profile

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	_ "net/http/pprof"
)

type Profiler struct {
	listenPort int
}

func NewProfiler() *Profiler {
	portStr := os.Getenv("PPROF_PORT")
	port, err := strconv.Atoi(portStr)
	if err != nil || portStr == "" {
		port = 6060
	}
	return &Profiler{
		listenPort: port,
	}
}

func (p *Profiler) Run() {
	address := fmt.Sprintf("localhost:%d", p.listenPort)
	http.ListenAndServe(address, nil)
}
