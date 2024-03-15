package bypass

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	nd "istio.io/istio/cni/pkg/nodeagent"
	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	log = logger.NewLoggerField("bypass")
	FS  embed.FS
)

const (
	DefaultInformerSyncPeriod = 30 * time.Second
	LabelSelectorBypass       = "kmesh.net/bypass=enabled"
)

func StartByPassController(client kubernetes.Interface) error {
	stopChan := make(chan struct{})
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
			options.LabelSelector = LabelSelectorBypass
		}))

	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)

	podInformer := informerFactory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}

			log.Infof("%s/%s: ADDED", pod.GetNamespace(), pod.GetName())
			enableSidecar, _ := checkSidecar(client, pod)
			if !enableSidecar {
				log.Info("do not need add iptables rules, pod is not managed by sidecar")
				return
			}

			nspath, _ := getnspath(pod)
			addIptables(nspath)
		},
		DeleteFunc: func(obj interface{}) {
			if _, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}

			if isPodBeingDeleted(pod) {
				log.Debugf("%s/%s: Pod is being deleted, skipping further processing", pod.GetNamespace(), pod.GetName())
				return
			}
			enableSidecar, _ := checkSidecar(client, pod)
			if !enableSidecar {
				log.Info("do not need delete iptables rules, pod is not managed by sidecar")
				return
			}
			log.Infof("%s/%s: DELETED", pod.GetNamespace(), pod.GetName())
			nspath, _ := getnspath(pod)
			deleteIptables(nspath)
		},
	})

	go podInformer.Run(stopChan)

	return nil
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func addIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-I", "PREROUTING", "1", "-j", "RETURN"},
		{"-t", "nat", "-I", "OUTPUT", "1", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running add iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				return fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter ns path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func deleteIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-j", "RETURN"},
		{"-t", "nat", "-D", "OUTPUT", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running delete iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				err = fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
				log.Error(err)
				return err
			}
		}
		return nil
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter ns path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func checkSidecar(client kubernetes.Interface, pod *corev1.Pod) (bool, error) {
	namespace, err := client.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	injectLabel := namespace.Labels["istio-injection"]
	if injectLabel == "enabled" {
		return true, nil
	}

	if _, ok := pod.Annotations["sidecar.istio.io/inject"]; ok {
		return true, nil
	}

	return false, nil
}

func getnspath(pod *corev1.Pod) (string, error) {
	res, err := FindNetnsForPod(pod)
	if err != nil {
		return "", err
	}
	res = path.Join("/proc", res)
	return res, nil
}

func BuiltinOrDir(dir string) fs.FS {
	if dir == "" {
		return FS
	}
	return os.DirFS(dir)
}

func FindNetnsForPod(pod *corev1.Pod) (string, error) {
	netnsObserved := sets.New[uint64]()
	fd := BuiltinOrDir("/proc")

	entries, err := fs.ReadDir(fd, ".")
	if err != nil {
		return "", err
	}

	desiredUID := pod.UID
	for _, entry := range entries {
		res, err := processEntry(fd, netnsObserved, desiredUID, entry)
		if err != nil {
			log.Debugf("error processing entry: %s %v", entry.Name(), err)
			continue
		}
		if res != "" {
			return res, nil
		}
	}
	return "", fmt.Errorf("No matching network namespace found")
}

func isNotNumber(r rune) bool {
	return r < '0' || r > '9'
}

func isProcess(entry fs.DirEntry) bool {
	if !entry.IsDir() {
		return false
	}

	if strings.IndexFunc(entry.Name(), isNotNumber) != -1 {
		return false
	}
	return true
}

// copied from istio/cni/pkg/nodeagent/podcgroupns.go
func processEntry(proc fs.FS, netnsObserved sets.Set[uint64], filter types.UID, entry fs.DirEntry) (string, error) {
	if !isProcess(entry) {
		return "", nil
	}

	netnsName := path.Join(entry.Name(), "ns", "net")
	fi, err := fs.Stat(proc, netnsName)
	if err != nil {
		return "", err
	}

	inode, err := nd.GetInode(fi)
	if err != nil {
		return "", err
	}
	if _, ok := netnsObserved[inode]; ok {
		log.Debugf("netns: %d already processed. skipping", inode)
		return "", nil
	}

	cgroup, err := proc.Open(path.Join(entry.Name(), "cgroup"))
	if err != nil {
		return "", nil
	}
	defer cgroup.Close()

	var cgroupData bytes.Buffer
	_, err = io.Copy(&cgroupData, cgroup)
	if err != nil {
		return "", nil
	}

	uid, _, err := nd.GetPodUIDAndContainerID(cgroupData)
	if err != nil {
		return "", err
	}

	if filter != uid {
		return "", nil
	}

	log.Debugf("found pod to netns: %s %d", uid, inode)

	return netnsName, nil
}
